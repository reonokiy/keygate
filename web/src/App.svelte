<script lang="ts">
  import { onMount, tick } from 'svelte';
  import ApplicationCard from './ApplicationCard.svelte';
  import { getApplications, getIdentity, issueKey, revokeKey } from './api';
  import type { Application } from './api';

  let applications = $state<Application[]>([]);
  let subject = $state('');
  let status = $state('');
  let loading = $state(true);
  let newKey = $state('');
  let issuing = $state(false);
  let copied = $state(false);
  let dialog = $state<HTMLDialogElement>();
  let keyField = $state<HTMLTextAreaElement>();

  function report(error: unknown): void {
    status = error instanceof Error ? error.message : 'Request failed. Please try again.';
  }

  async function refresh(): Promise<void> {
    applications = await getApplications();
  }

  async function initialize(): Promise<void> {
    try {
      subject = (await getIdentity()).subject;
      await refresh();
    } catch (error) {
      report(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void initialize();
  });

  async function issue(appId: string, name: string): Promise<boolean> {
    if (issuing || newKey) return false;
    issuing = true;
    status = '';
    let issued = false;
    try {
      const result = await issueKey(appId, name);
      issued = true;
      newKey = result.key;
      copied = false;
      await tick();
      dialog?.showModal();
      await refresh();
    } catch (error) {
      report(error);
    } finally {
      issuing = false;
    }
    return issued;
  }

  async function revoke(appId: string, keyId: string): Promise<void> {
    status = '';
    try {
      await revokeKey(appId, keyId);
      await refresh();
    } catch (error) {
      report(error);
    }
  }

  function clearKey(): void {
    newKey = '';
    copied = false;
  }

  function closeKey(): void {
    clearKey();
    dialog?.close();
  }

  async function copyKey(): Promise<void> {
    const value = newKey;
    try {
      await navigator.clipboard.writeText(value);
      if (newKey === value && dialog?.open) copied = true;
    } catch {
      keyField?.focus();
      keyField?.select();
    }
  }
</script>

<main>
  <header>
    <span class="mark">K</span>
    <div>
      <h1>Keygate</h1>
      <p>Applications and my API keys</p>
    </div>
    <span id="identity">{subject}</span>
  </header>
  <section class="intro">
    <h2>Manage my API keys</h2>
    <p>Your administrator configures applications and API access rules. Generate API keys for configured applications and view or manage only your own keys.</p>
  </section>
  <p id="status" role="status" aria-live="polite">{status}</p>
  <section id="apps" aria-label="Applications" aria-busy={loading}>
    {#if loading}
      <p class="empty">Loading applications…</p>
    {:else if applications.length === 0 && !status}
      <p class="empty">Your administrator has not configured any applications yet. Contact your administrator to add an application before generating an API key.</p>
    {/if}
    {#each applications as app (app.id)}
      <ApplicationCard {app} issuanceBlocked={issuing || newKey.length > 0} onissue={issue} onrevoke={revoke} />
    {/each}
  </section>
  <dialog
    id="key-dialog"
    bind:this={dialog}
    aria-labelledby="key-dialog-title"
    oncancel={clearKey}
    onclose={clearKey}
  >
    <h2 id="key-dialog-title">API key generated</h2>
    <p>Save this key now. You will not be able to view it after closing this dialog.</p>
    <textarea
      id="new-key"
      bind:this={keyField}
      value={newKey}
      readonly
      aria-label="New API key"
      rows={4}
    ></textarea>
    <div class="row">
      <button id="copy-key" type="button" onclick={copyKey}>{copied ? 'Copied' : 'Copy key'}</button>
      <button id="close-key" type="button" class="secondary" onclick={closeKey}>Saved, close</button>
    </div>
  </dialog>
  <footer>Revocations usually take effect within 30 seconds, depending on your administrator's cache settings.</footer>
</main>
