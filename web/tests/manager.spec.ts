import { expect, test, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const appId = '11111111-1111-4111-8111-111111111111';
const secondAppId = '22222222-2222-4222-8222-222222222222';
const token = `kg-${'Ab'.repeat(23)}`;
const policy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

interface Key {
  id: string;
  name: string;
  created_at: number;
  revoked: boolean;
}

async function serveManager(page: Page, base: string, options: {
  empty?: boolean;
  failIssue?: boolean;
  failRefresh?: boolean;
  secondApp?: boolean;
  delayIssue?: boolean;
} = {}) {
  const keys: Key[] = [];
  const errors: string[] = [];
  const requests: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  await page.route('http://keygate.test/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    requests.push(`${request.method()} ${path}`);
    const asset = path === base ? 'index.html' : path.slice(base.length);
    if (path.startsWith(base) && ['index.html', 'app.js', 'style.css'].includes(asset)) {
      await route.fulfill({
        body: await readFile(new URL(`../dist/${asset}`, import.meta.url)),
        contentType: asset.endsWith('.html') ? 'text/html' : asset.endsWith('.js') ? 'text/javascript' : 'text/css',
        headers: { 'content-security-policy': policy },
      });
      return;
    }
    if (path.endsWith('/favicon.ico')) {
      await route.fulfill({ status: 204 });
    } else if (path === `${base}api/me`) {
      await route.fulfill({ json: { subject: 'alice', user_id: 'usr_alice' } });
    } else if (path === `${base}api/apps` && request.method() === 'GET') {
      if (options.failRefresh && keys.length > 0) {
        await route.fulfill({ status: 503, json: { error: 'application list unavailable' } });
      } else {
        const applications = [{ id: appId, name: 'Configured API', keys }];
        if (options.secondApp) applications.push({ id: secondAppId, name: 'Second API', keys: [] });
        await route.fulfill({ json: options.empty ? [] : applications });
      }
    } else if ([appId, secondAppId].some((id) => path === `${base}api/apps/${id}/keys`) && request.method() === 'POST') {
      expect(request.headers()['x-keygate-csrf']).toBe('1');
      expect(request.headers()['content-type']).toBe('application/json');
      if (options.failIssue) {
        await route.fulfill({ status: 409, json: { error: 'concurrent update; reload and retry' } });
      } else {
        if (options.delayIssue) await new Promise((resolve) => setTimeout(resolve, 250));
        const body = request.postDataJSON() as { name: string };
        const id = `key-${keys.length + 1}`;
        keys.push({ id, name: body.name, created_at: 1_700_000_000, revoked: false });
        await route.fulfill({ status: 201, json: { id, key: token } });
      }
    } else if (path.startsWith(`${base}api/apps/${appId}/keys/`) && request.method() === 'DELETE') {
      expect(request.headers()['x-keygate-csrf']).toBe('1');
      const key = keys.find((entry) => path.endsWith(`/${entry.id}`));
      expect(key).toBeDefined();
      key!.revoked = true;
      await route.fulfill({ status: 204 });
    } else {
      await route.fulfill({ status: 404 });
    }
  });
  await page.goto(`http://keygate.test${base}`);
  return { errors, requests };
}

for (const base of ['/', '/keys/']) {
  test(`key lifecycle works under ${base} with production CSP`, async ({ page }, testInfo) => {
    if (base === '/keys/') await page.setViewportSize({ width: 390, height: 844 });
    const { errors, requests } = await serveManager(page, base);
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page.getByRole('heading', { name: 'Configured API' })).toBeVisible();
    await expect(page.locator('#identity')).toHaveText('alice');
    await expect(page.locator('#create-app')).toHaveCount(0);
    await page.getByLabel('Key name').fill('<script>alert("key name")</script>');
    await page.getByRole('button', { name: 'Generate key' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByLabel('New API key')).toHaveValue(token);
    // The fixture's HTTP origin has no clipboard API; exercise the selection fallback.
    await page.getByRole('button', { name: 'Copy key' }).click();
    await expect.poll(() => page.getByLabel('New API key').evaluate((element) => {
      const field = element as HTMLTextAreaElement;
      return field.selectionEnd - field.selectionStart;
    })).toBe(token.length);
    await page.getByRole('button', { name: 'Saved, close' }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();
    await expect(page.getByLabel('New API key')).toHaveValue('');
    await expect(page.locator('li strong')).toHaveText('<script>alert("key name")</script>');
    await expect(page.locator('li script')).toHaveCount(0);
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Revoke', exact: true }).click();
    await expect(page.locator('li')).toContainText('Revoked');
    await expect(page.getByRole('button', { name: 'Revoke', exact: true })).toHaveCount(0);
    await page.getByLabel('Key name').fill('second key');
    await page.getByRole('button', { name: 'Generate key' }).click();
    await expect(page.getByLabel('New API key')).toHaveValue(token);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).not.toBeVisible();
    await expect(page.getByLabel('New API key')).toHaveValue('');
    await expect(page.locator('body')).not.toContainText(/[\u3400-\u9fff]/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath('manager.png'), fullPage: true });
    expect(requests).not.toContain(`POST ${base}api/apps`);
    expect(errors).toEqual([]);
  });
}

test('empty catalog offers no application creation', async ({ page }) => {
  await serveManager(page, '/', { empty: true });
  await expect(page.locator('#apps')).toContainText('administrator');
  await expect(page.locator('form')).toHaveCount(0);
});

test('issuance failure is shown and allows retry', async ({ page }) => {
  await serveManager(page, '/', { failIssue: true });
  await page.getByLabel('Key name').fill('script');
  await page.getByRole('button', { name: 'Generate key' }).click();
  await expect(page.getByRole('status')).toContainText('concurrent update; reload and retry');
  await expect(page.getByRole('button', { name: 'Generate key' })).toBeEnabled();
  await expect(page.getByRole('dialog')).not.toBeVisible();
});

test('successful issuance stays visible and clears the form if refreshing fails', async ({ page }) => {
  await serveManager(page, '/', { failRefresh: true });
  await page.getByLabel('Key name').fill('script');
  await page.getByRole('button', { name: 'Generate key' }).click();
  await expect(page.getByLabel('New API key')).toHaveValue(token);
  await expect(page.getByRole('status')).toContainText('application list unavailable');
  await expect(page.getByLabel('Key name')).toHaveValue('');
});

test('issuing for another application cannot overwrite an unsaved key', async ({ page }) => {
  const { requests } = await serveManager(page, '/', { secondApp: true, delayIssue: true });
  await page.getByLabel('Key name').nth(0).fill('first');
  await page.getByLabel('Key name').nth(1).fill('second');
  await page.getByRole('button', { name: 'Generate key' }).nth(0).click();
  await expect(page.getByRole('button', { name: 'Generate key' }).nth(1)).toBeDisabled();
  await page.locator('form').nth(1).evaluate((form) => {
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
  await expect(page.getByLabel('New API key')).toHaveValue(token);
  expect(requests.filter((request) => request.startsWith('POST '))).toHaveLength(1);
  await expect(page.getByRole('button', { name: 'Generate key' }).nth(1)).toBeDisabled();
  await page.getByRole('button', { name: 'Saved, close' }).click();
  await expect(page.getByRole('button', { name: 'Generate key' }).nth(1)).toBeEnabled();
});
