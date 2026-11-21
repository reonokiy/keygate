<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import CircleAlert from '@lucide/svelte/icons/circle-alert';
  import Copy from '@lucide/svelte/icons/copy';
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Lock from '@lucide/svelte/icons/lock';
  import Moon from '@lucide/svelte/icons/moon';
  import PanelLeft from '@lucide/svelte/icons/panel-left';
  import Sun from '@lucide/svelte/icons/sun';
  import Terminal from '@lucide/svelte/icons/terminal';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import X from '@lucide/svelte/icons/x';
  import { onMount, tick } from 'svelte';
  import ApplicationCard from './ApplicationCard.svelte';
  import { getApplications, getIdentity, issueKey, revokeKey } from './api';
  import type { ApiKey, Application } from './api';
  import Alert from './lib/components/ui/alert.svelte';
  import Button from './lib/components/ui/button.svelte';
  import Input from './lib/components/ui/input.svelte';

  let applications = $state<Application[]>([]);
  let selectedAppId = $state('');
  let subject = $state('');
  let userId = $state('');
  let status = $state('');
  let loading = $state(true);

  let dialogApp = $state<Application | null>(null);
  let draftKeyName = $state('');
  let newKey = $state('');
  let issuedKeyName = $state('');
  let issuing = $state(false);
  let copied = $state(false);

  let pendingRevoke = $state<{ appId: string; key: ApiKey } | null>(null);
  let revokingKeyId = $state<string | null>(null);

  let darkTheme = $state(false);

  let keyDialog = $state<HTMLDialogElement>();
  let revokeDialog = $state<HTMLDialogElement>();
  let mobileSheet = $state<HTMLDialogElement>();
  let keyNameInput = $state<HTMLInputElement>();
  let keyField = $state<HTMLTextAreaElement>();

  let selectedApp = $derived(
    applications.find((app) => app.id === selectedAppId) ?? applications[0] ?? null,
  );

  let avatarInitial = $derived((subject.trim().charAt(0) || '?').toUpperCase());

  function report(error: unknown): void {
    status = error instanceof Error ? error.message : 'Request failed. Please try again.';
  }

  function applyTheme(isDark: boolean): void {
    darkTheme = isDark;
    const root = document.documentElement;
    root.classList.toggle('dark', isDark);
    root.classList.toggle('light', !isDark);
  }

  function toggleTheme(): void {
    const next = !darkTheme;
    applyTheme(next);
    try {
      localStorage.setItem('keygate-theme', next ? 'dark' : 'light');
    } catch {
      // Ignore storage access restrictions.
    }
  }

  async function refresh(): Promise<void> {
    const nextApps = await getApplications();
    applications = nextApps;
    if (!nextApps.some((app) => app.id === selectedAppId)) {
      selectedAppId = nextApps[0]?.id ?? '';
    }
  }

  async function initialize(): Promise<void> {
    try {
      const identity = await getIdentity();
      subject = identity.subject;
      userId = identity.user_id;
      await refresh();
    } catch (error) {
      report(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    try {
      const saved = localStorage.getItem('keygate-theme');
      if (saved === 'dark' || saved === 'light') {
        applyTheme(saved === 'dark');
      } else {
        darkTheme = window.matchMedia('(prefers-color-scheme: dark)').matches;
      }
    } catch {
      darkTheme = window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    void initialize();
  });

  function selectApp(appId: string): void {
    selectedAppId = appId;
    if (mobileSheet?.open) mobileSheet.close();
  }

  function openMobileSheet(): void {
    mobileSheet?.showModal();
  }

  function closeMobileSheet(): void {
    if (mobileSheet?.open) mobileSheet.close();
  }

  function handleSheetBackdropClick(event: MouseEvent): void {
    if (event.target === mobileSheet) closeMobileSheet();
  }

  async function openIssueDialog(app: Application): Promise<void> {
    if (issuing || newKey) return;
    status = '';
    dialogApp = app;
    draftKeyName = '';
    issuedKeyName = '';
    copied = false;
    await tick();
    if (!keyDialog?.open) keyDialog?.showModal();
    keyNameInput?.focus();
  }

  async function submitIssue(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const target = dialogApp;
    if (!target || issuing || newKey) return;
    const trimmed = draftKeyName.trim();
    if (!trimmed) return;
    issuing = true;
    status = '';
    try {
      const result = await issueKey(target.id, draftKeyName);
      newKey = result.key;
      issuedKeyName = trimmed;
      draftKeyName = '';
      copied = false;
      await tick();
      await refresh();
    } catch (error) {
      report(error);
    } finally {
      issuing = false;
    }
  }

  function clearKeyDialog(): void {
    newKey = '';
    issuedKeyName = '';
    draftKeyName = '';
    dialogApp = null;
    copied = false;
  }

  function closeKeyDialog(): void {
    if (issuing) return;
    clearKeyDialog();
    if (keyDialog?.open) keyDialog.close();
  }

  function handleKeyDialogCancel(event: Event): void {
    if (issuing) {
      event.preventDefault();
      return;
    }
    clearKeyDialog();
  }

  async function copyKey(): Promise<void> {
    const value = newKey;
    try {
      await navigator.clipboard.writeText(value);
      if (newKey === value && keyDialog?.open) copied = true;
    } catch {
      keyField?.focus();
      keyField?.select();
    }
  }

  async function requestRevoke(app: Application, key: ApiKey): Promise<void> {
    if (revokingKeyId !== null) return;
    pendingRevoke = { appId: app.id, key };
    await tick();
    revokeDialog?.showModal();
  }

  function closeRevokeDialog(): void {
    if (revokingKeyId !== null) return;
    pendingRevoke = null;
    if (revokeDialog?.open) revokeDialog.close();
  }

  function handleRevokeCancel(event: Event): void {
    if (revokingKeyId !== null) {
      event.preventDefault();
      return;
    }
    pendingRevoke = null;
  }

  async function confirmRevoke(): Promise<void> {
    const target = pendingRevoke;
    if (!target || revokingKeyId !== null) return;
    revokingKeyId = target.key.id;
    status = '';
    try {
      await revokeKey(target.appId, target.key.id);
      await refresh();
      pendingRevoke = null;
      if (revokeDialog?.open) revokeDialog.close();
    } catch (error) {
      report(error);
      pendingRevoke = null;
      if (revokeDialog?.open) revokeDialog.close();
    } finally {
      revokingKeyId = null;
    }
  }

  function activeKeyCount(app: Application): number {
    return app.keys.filter((key) => !key.revoked).length;
  }
</script>

{#snippet sidebarContent(inSheet: boolean)}
  <div class="flex h-14 shrink-0 items-center justify-between border-b border-sidebar-border px-4">
    <div class="flex items-center gap-2.5">
      <span
        class="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground"
        aria-hidden="true"
      >
        <KeyRound class="size-3.5" />
      </span>
      <span class="text-sm font-semibold tracking-tight text-sidebar-foreground">Keygate</span>
    </div>
    {#if inSheet}
      <Button variant="ghost" size="iconSm" onclick={closeMobileSheet} aria-label="Close menu">
        <X class="size-4" />
      </Button>
    {/if}
  </div>

  <div class="flex-1 overflow-y-auto px-3 py-4">
    <p class="px-2 pb-1.5 text-xs font-medium text-muted-foreground">Applications</p>
    {#if loading}
      <div class="space-y-1.5 px-1">
        <div class="h-8 w-full animate-pulse rounded-md bg-muted"></div>
        <div class="h-8 w-full animate-pulse rounded-md bg-muted"></div>
      </div>
    {:else if applications.length === 0}
      <p class="px-2 py-1.5 text-xs text-muted-foreground">None assigned</p>
    {:else}
      <nav class="flex flex-col gap-0.5" aria-label="Authorized applications">
        {#each applications as app (app.id)}
          {@const isSelected = selectedApp?.id === app.id}
          <button
            type="button"
            aria-current={isSelected ? 'page' : undefined}
            class="flex h-8 w-full cursor-pointer items-center justify-between gap-2 rounded-md px-2 text-left text-sm transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring {isSelected
              ? 'bg-sidebar-accent font-medium text-sidebar-accent-foreground'
              : 'text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground'}"
            onclick={() => selectApp(app.id)}
          >
            <span class="flex min-w-0 items-center gap-2">
              <Terminal class="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span class="truncate">{app.name}</span>
            </span>
            <span class="shrink-0 text-xs text-muted-foreground tabular-nums">
              {activeKeyCount(app)}
            </span>
          </button>
        {/each}
      </nav>
    {/if}
  </div>

  <div class="border-t border-sidebar-border px-4 py-3">
    <p class="text-xs leading-relaxed text-muted-foreground">
      Applications and access groups are configured by your administrator.
    </p>
  </div>
{/snippet}

<div class="flex min-h-screen bg-background text-foreground">
  <aside
    class="hidden w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex"
    aria-label="Sidebar"
  >
    {@render sidebarContent(false)}
  </aside>

  <div class="flex min-w-0 flex-1 flex-col">
    <header class="sticky top-0 z-10 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border bg-background/95 px-4 backdrop-blur-xs sm:px-6">
      <div class="flex min-w-0 items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          class="md:hidden"
          onclick={openMobileSheet}
          aria-label="Open applications menu"
        >
          <PanelLeft class="size-4" />
        </Button>
        <div class="h-4 w-px bg-border md:hidden" aria-hidden="true"></div>

        <nav class="flex min-w-0 items-center gap-1.5 text-sm" aria-label="Breadcrumb">
          <span class="hidden text-muted-foreground sm:inline">API Keys</span>
          {#if selectedApp}
            <ChevronRight class="hidden size-3.5 shrink-0 text-muted-foreground/60 sm:inline" aria-hidden="true" />
            <span class="truncate font-medium text-foreground">{selectedApp.name}</span>
          {:else}
            <span class="font-medium text-foreground sm:hidden">Keygate</span>
          {/if}
        </nav>
      </div>

      <div class="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          onclick={toggleTheme}
          aria-label="Toggle color theme"
          title={darkTheme ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {#if darkTheme}
            <Sun class="size-4" />
          {:else}
            <Moon class="size-4" />
          {/if}
        </Button>

        <div
          class="flex max-w-44 items-center gap-2 pl-1 text-xs sm:max-w-64"
          title={userId ? `Signed in (${userId})` : undefined}
        >
          <span
            class="flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium text-foreground"
            aria-hidden="true"
          >
            {avatarInitial}
          </span>
          <span id="identity" class="truncate font-medium text-foreground">{subject}</span>
        </div>
      </div>
    </header>

    <main class="mx-auto w-full max-w-4xl flex-1 px-4 py-6 sm:px-6 sm:py-8">
      <div id="status" role="status" aria-live="polite" class={status ? 'mb-6' : 'sr-only'}>
        {#if status}
          <Alert variant="destructive">
            <CircleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <div class="min-w-0 flex-1">
              <p class="font-medium">Request failed</p>
              <p class="mt-0.5 text-xs opacity-90">{status}</p>
            </div>
            <Button
              variant="ghost"
              size="iconSm"
              class="text-destructive hover:bg-destructive/10 hover:text-destructive"
              onclick={() => (status = '')}
              aria-label="Dismiss error"
            >
              <X class="size-3.5" />
            </Button>
          </Alert>
        {/if}
      </div>

      <section id="apps" aria-label="Applications" aria-busy={loading}>
        {#if loading}
          <div class="space-y-6">
            <div class="flex items-center justify-between gap-4">
              <div class="space-y-2">
                <div class="h-7 w-44 animate-pulse rounded bg-muted"></div>
                <div class="h-4 w-64 max-w-full animate-pulse rounded bg-muted"></div>
              </div>
              <div class="h-9 w-32 animate-pulse rounded-md bg-muted"></div>
            </div>
            <div class="h-48 w-full animate-pulse rounded-md border border-border bg-muted/30"></div>
            <p class="text-xs text-muted-foreground">Loading applications…</p>
          </div>
        {:else if applications.length === 0 && !status}
          <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-border px-6 py-16 text-center">
            <div
              class="mb-3 flex size-10 items-center justify-center rounded-lg border border-border bg-muted/50 text-muted-foreground"
              aria-hidden="true"
            >
              <Lock class="size-4" />
            </div>
            <h2 class="text-base font-semibold text-foreground">No authorized applications</h2>
            <p class="mt-1.5 max-w-md text-sm text-muted-foreground">
              No applications are authorized for your account. Ask your administrator to assign the application group before generating an API key.
            </p>
          </div>
        {:else if selectedApp}
          <ApplicationCard
            app={selectedApp}
            issuanceBlocked={issuing || newKey.length > 0}
            {revokingKeyId}
            onopenissue={openIssueDialog}
            onrequestrevoke={requestRevoke}
          />
        {/if}
      </section>
    </main>
  </div>
</div>

<dialog
  id="mobile-nav-sheet"
  class="sheet"
  bind:this={mobileSheet}
  aria-label="Applications navigation"
  onclick={handleSheetBackdropClick}
>
  <div class="flex h-full flex-col border-r border-sidebar-border bg-sidebar shadow-xl">
    {@render sidebarContent(true)}
  </div>
</dialog>

<dialog
  id="key-dialog"
  bind:this={keyDialog}
  aria-labelledby="key-dialog-title"
  oncancel={handleKeyDialogCancel}
  onclose={clearKeyDialog}
>
  <div class="flex flex-col gap-4 rounded-lg border border-border bg-popover p-6 text-popover-foreground shadow-lg">
    {#if newKey}
      <div class="space-y-1.5">
        <h2 id="key-dialog-title" class="text-base font-semibold tracking-tight text-foreground">
          API key generated
        </h2>
        <p class="text-sm text-muted-foreground">
          {#if dialogApp?.name || issuedKeyName}
            Created <strong class="font-medium text-foreground">{issuedKeyName}</strong>
            {#if dialogApp?.name} for {dialogApp.name}{/if}.
          {:else}
            Save this key now.
          {/if}
        </p>
      </div>

      <Alert variant="warning">
        <TriangleAlert class="mt-0.5 size-4 shrink-0 text-warning" aria-hidden="true" />
        <div class="min-w-0 flex-1">
          <p class="text-xs font-medium text-foreground">Shown once only</p>
          <p class="mt-0.5 text-xs text-muted-foreground">
            You will not be able to view this key after closing this dialog.
          </p>
        </div>
      </Alert>

      {#if status}
        <Alert variant="destructive">
          <CircleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <p class="text-xs">{status}</p>
        </Alert>
      {/if}

      <textarea
        id="new-key"
        bind:this={keyField}
        value={newKey}
        readonly
        aria-label="New API key"
        rows={3}
        class="w-full resize-none rounded-md border border-input bg-muted px-3 py-2.5 font-mono text-xs leading-relaxed break-all text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30"
      ></textarea>

      <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button id="copy-key" variant="outline" onclick={copyKey}>
          {#if copied}
            <Check class="size-4 text-success" />
            Copied
          {:else}
            <Copy class="size-4" />
            Copy key
          {/if}
        </Button>
        <Button id="close-key" variant="default" onclick={closeKeyDialog}>Saved, close</Button>
      </div>
    {:else}
      <div class="flex items-start justify-between gap-4">
        <div class="space-y-1.5">
          <h2 id="key-dialog-title" class="text-base font-semibold tracking-tight text-foreground">
            Generate API key
          </h2>
          <p class="text-sm text-muted-foreground">
            Create a new API key{#if dialogApp} for <strong class="font-medium text-foreground">{dialogApp.name}</strong>{/if}. The secret is shown only once.
          </p>
        </div>
        <Button
          variant="ghost"
          size="iconSm"
          disabled={issuing}
          onclick={closeKeyDialog}
          aria-label="Close dialog"
          class="-mt-1 -mr-1 text-muted-foreground"
        >
          <X class="size-4" />
        </Button>
      </div>

      {#if status}
        <Alert variant="destructive">
          <CircleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <p class="text-xs">{status}</p>
        </Alert>
      {/if}

      <form id="generate-key-form" class="space-y-4" onsubmit={submitIssue}>
        <div class="space-y-2">
          <label class="block text-sm font-medium text-foreground" for="key-name-input">
            Key name
          </label>
          <Input
            id="key-name-input"
            bind:ref={keyNameInput}
            bind:value={draftKeyName}
            placeholder="e.g. Local development"
            required
            maxlength={128}
            autocomplete="off"
            aria-label="Key name"
            disabled={issuing}
          />
          <p class="text-xs text-muted-foreground">
            Use a descriptive name so you can identify and revoke this key later.
          </p>
        </div>

        <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button variant="outline" disabled={issuing} onclick={closeKeyDialog}>Cancel</Button>
          <Button type="submit" disabled={issuing || !draftKeyName.trim()}>
            {issuing ? 'Generating…' : 'Create key'}
          </Button>
        </div>
      </form>
    {/if}
  </div>
</dialog>

<dialog
  id="revoke-dialog"
  role="alertdialog"
  bind:this={revokeDialog}
  aria-labelledby="revoke-dialog-title"
  aria-describedby="revoke-dialog-description"
  oncancel={handleRevokeCancel}
  onclose={() => {
    if (revokingKeyId === null) pendingRevoke = null;
  }}
>
  <div class="flex flex-col gap-4 rounded-lg border border-border bg-popover p-6 text-popover-foreground shadow-lg">
    <div class="space-y-1.5">
      <h2 id="revoke-dialog-title" class="text-base font-semibold tracking-tight text-foreground">
        Revoke API key?
      </h2>
      <p id="revoke-dialog-description" class="text-sm text-muted-foreground">
        This will permanently revoke
        <strong class="break-words font-medium text-foreground">“{pendingRevoke?.key.name ?? ''}”</strong>.
        Any client using this key will lose access within 30 seconds.
      </p>
    </div>

    <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
      <Button
        id="cancel-revoke"
        variant="outline"
        disabled={revokingKeyId !== null}
        onclick={closeRevokeDialog}
      >
        Cancel
      </Button>
      <Button
        id="confirm-revoke"
        variant="destructive"
        disabled={revokingKeyId !== null}
        onclick={confirmRevoke}
      >
        {revokingKeyId !== null ? 'Revoking…' : 'Revoke key'}
      </Button>
    </div>
  </div>
</dialog>
