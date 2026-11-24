import { expect, test, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const appId = '11111111-1111-4111-8111-111111111111';
const secondAppId = '22222222-2222-4222-8222-222222222222';
const token = `kg-${'Ab'.repeat(23)}`;
const policy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const tinyPng = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+X2S8AAAAASUVORK5CYII=',
  'base64',
);

interface Key {
  id: string;
  name: string;
  created_at: number;
  revoked: boolean;
}

interface MockIdentity {
  subject: string;
  user_id: string;
  name?: string;
  username?: string;
  picture?: string;
}

async function serveManager(page: Page, base: string, options: {
  empty?: boolean;
  failIssue?: boolean;
  failRefresh?: boolean;
  secondApp?: boolean;
  delayIssue?: boolean;
  identity?: MockIdentity;
  avatarStatus?: number;
} = {}) {
  const keysByApp = new Map<string, Key[]>([
    [appId, []],
    [secondAppId, []],
  ]);
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
    } else if (path === '/avatar.png') {
      if (options.avatarStatus && options.avatarStatus !== 200) {
        await route.fulfill({ status: options.avatarStatus });
      } else {
        await route.fulfill({ body: tinyPng, contentType: 'image/png' });
      }
    } else if (path === `${base}api/me`) {
      await route.fulfill({
        json: options.identity ?? { subject: 'alice', user_id: 'usr_alice' },
      });
    } else if (path === `${base}api/apps` && request.method() === 'GET') {
      const totalKeys = [...keysByApp.values()].reduce((sum, list) => sum + list.length, 0);
      if (options.failRefresh && totalKeys > 0) {
        await route.fulfill({ status: 503, json: { error: 'application list unavailable' } });
      } else {
        const applications = [{ id: appId, name: 'Configured API', keys: keysByApp.get(appId) ?? [] }];
        if (options.secondApp) {
          applications.push({ id: secondAppId, name: 'Second API', keys: keysByApp.get(secondAppId) ?? [] });
        }
        await route.fulfill({ json: options.empty ? [] : applications });
      }
    } else if ([appId, secondAppId].some((id) => path === `${base}api/apps/${id}/keys`) && request.method() === 'POST') {
      expect(request.headers()['x-keygate-csrf']).toBe('1');
      expect(request.headers()['content-type']).toBe('application/json');
      const targetAppId = [appId, secondAppId].find((id) => path === `${base}api/apps/${id}/keys`)!;
      if (options.failIssue) {
        await route.fulfill({ status: 409, json: { error: 'concurrent update; reload and retry' } });
      } else {
        if (options.delayIssue) await new Promise((resolve) => setTimeout(resolve, 250));
        const body = request.postDataJSON() as { name: string };
        const keys = keysByApp.get(targetAppId)!;
        const id = `key-${keys.length + 1}`;
        keys.push({ id, name: body.name, created_at: 1_700_000_000, revoked: false });
        await route.fulfill({ status: 201, json: { id, key: token } });
      }
    } else if (path.startsWith(`${base}api/apps/${appId}/keys/`) && request.method() === 'DELETE') {
      expect(request.headers()['x-keygate-csrf']).toBe('1');
      const key = keysByApp.get(appId)!.find((entry) => path.endsWith(`/${entry.id}`));
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
    const { errors, requests } = await serveManager(page, base, { secondApp: true });
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page.getByRole('heading', { name: 'Configured API' })).toBeVisible();
    await expect(page.locator('#identity')).toHaveText('alice');
    await expect(page.locator('#create-app')).toHaveCount(0);

    await page.getByRole('button', { name: 'Generate key' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.getByLabel('Key name').fill('<script>alert("key name")</script>');
    await page.getByRole('button', { name: 'Create key' }).click();
    await expect(page.getByLabel('New API key')).toHaveValue(token);

    // The fixture's HTTP origin has no clipboard API; exercise the selection fallback.
    await page.getByRole('button', { name: 'Copy key' }).click();
    await expect.poll(() => page.getByLabel('New API key').evaluate((element) => {
      const field = element as HTMLTextAreaElement;
      return field.selectionEnd - field.selectionStart;
    })).toBe(token.length);

    await page.getByRole('button', { name: 'Saved, close' }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();
    await expect(page.getByLabel('New API key')).toHaveCount(0);
    await expect(page.locator('tbody strong')).toHaveText('<script>alert("key name")</script>');
    await expect(page.locator('tbody script')).toHaveCount(0);

    await page.getByRole('button', { name: 'Revoke', exact: true }).click();
    await expect(page.getByRole('alertdialog')).toBeVisible();
    await page.getByRole('button', { name: 'Revoke key' }).click();
    await expect(page.getByRole('alertdialog')).not.toBeVisible();
    await expect(page.locator('tbody tr')).toContainText('Revoked');
    await expect(page.getByRole('button', { name: 'Revoke', exact: true })).toHaveCount(0);

    await page.getByRole('button', { name: 'Generate key' }).click();
    await page.getByLabel('Key name').fill('second key');
    await page.getByRole('button', { name: 'Create key' }).click();
    await expect(page.getByLabel('New API key')).toHaveValue(token);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).not.toBeVisible();
    await expect(page.getByLabel('New API key')).toHaveCount(0);

    // Status tabs and search filter work.
    await page.getByRole('tab', { name: /Active/ }).click();
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await expect(page.locator('tbody tr')).toContainText('second key');
    await page.getByRole('tab', { name: /Revoked/ }).click();
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await expect(page.locator('tbody tr')).toContainText('<script>alert("key name")</script>');
    await page.getByRole('tab', { name: /All/ }).click();
    await page.getByLabel('Search keys').fill('second');
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.getByRole('button', { name: 'Reset' }).click();
    await expect(page.locator('tbody tr')).toHaveCount(2);

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
  await expect(page.getByRole('button', { name: 'Generate key' })).toHaveCount(0);
});

test('issuance failure is shown and allows retry', async ({ page }) => {
  await serveManager(page, '/', { failIssue: true });
  await page.getByRole('button', { name: 'Generate key' }).click();
  await page.getByLabel('Key name').fill('script');
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByRole('status')).toContainText('concurrent update; reload and retry');
  await expect(page.getByRole('button', { name: 'Create key' })).toBeEnabled();
  await expect(page.getByLabel('New API key')).toHaveCount(0);
});

test('successful issuance stays visible and clears draft if refreshing fails', async ({ page }) => {
  await serveManager(page, '/', { failRefresh: true });
  await page.getByRole('button', { name: 'Generate key' }).click();
  await page.getByLabel('Key name').fill('script');
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByLabel('New API key')).toHaveValue(token);
  await expect(page.getByRole('status')).toContainText('application list unavailable');
  await page.getByRole('button', { name: 'Saved, close' }).click();
  await page.getByRole('button', { name: 'Generate key' }).click();
  await expect(page.getByLabel('Key name')).toHaveValue('');
});

test('in-flight issuance blocks duplicate submission and prevents overwriting an unsaved key', async ({ page }) => {
  const { requests } = await serveManager(page, '/', { secondApp: true, delayIssue: true });
  await page.getByRole('button', { name: 'Generate key' }).click();
  await page.getByLabel('Key name').fill('first');
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByRole('button', { name: 'Generating…' })).toBeDisabled();
  await page.locator('#generate-key-form').evaluate((form) => {
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
  await expect(page.getByLabel('New API key')).toHaveValue(token);
  expect(requests.filter((request) => request.startsWith('POST '))).toHaveLength(1);
  await page.getByRole('button', { name: 'Saved, close' }).click();
  await expect(page.getByRole('button', { name: 'Generate key' })).toBeEnabled();
});

test('switching applications works via desktop sidebar and mobile sheet', async ({ page }) => {
  const desktop = await serveManager(page, '/', { secondApp: true });
  await page.locator('aside').getByRole('button', { name: /Second API/ }).click();
  await expect(page.getByRole('heading', { name: 'Second API' })).toBeVisible();
  expect(desktop.errors).toEqual([]);

  await page.setViewportSize({ width: 390, height: 844 });
  const mobile = await serveManager(page, '/', { secondApp: true });
  await expect(page.getByRole('heading', { name: 'Configured API' })).toBeVisible();
  await page.getByRole('button', { name: 'Open applications menu' }).click();
  await page.locator('#mobile-nav-sheet').getByRole('button', { name: /Second API/ }).click();
  await expect(page.getByRole('heading', { name: 'Second API' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(mobile.errors).toEqual([]);
});

test('renders OIDC display name and avatar with fallback on image error', async ({ page }) => {
  const uuid = '01950000-0000-7000-8000-000000000001';
  const { errors } = await serveManager(page, '/', {
    identity: {
      subject: uuid,
      user_id: 'usr_alice',
      name: 'Alice Example',
      username: 'alice',
      picture: 'http://keygate.test/avatar.png',
    },
  });
  await expect(page.locator('#identity')).toHaveText('Alice Example');
  await expect(page.locator('#identity')).not.toContainText(uuid);
  const avatar = page.locator('header img[alt="Alice Example"]');
  await expect(avatar).toBeVisible();
  await expect.poll(() => avatar.evaluate((img) => {
    const el = img as HTMLImageElement;
    return el.complete && el.naturalWidth > 0;
  })).toBe(true);
  expect(errors).toEqual([]);

  await serveManager(page, '/', {
    identity: {
      subject: uuid,
      user_id: 'usr_alice',
      username: 'alice',
      picture: 'http://keygate.test/avatar.png',
    },
    avatarStatus: 404,
  });
  await expect(page.locator('#identity')).toHaveText('alice');
  await expect(page.locator('header img')).toHaveCount(0);
});

test('theme toggle and reduced-motion animations work cleanly under production CSP', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const { errors } = await serveManager(page, '/', { secondApp: true });
  await page.getByRole('button', { name: 'Toggle color theme' }).click();
  await expect(page.locator('html')).toHaveClass(/dark|light/);
  await page.getByRole('button', { name: 'Generate key' }).click();
  await page.getByLabel('Key name').fill('animated key');
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByLabel('New API key')).toHaveValue(token);
  await page.getByRole('button', { name: 'Saved, close' }).click();
  await expect(page.locator('tbody tr.kg-row-highlight')).toHaveCount(1);
  expect(errors).toEqual([]);
});
