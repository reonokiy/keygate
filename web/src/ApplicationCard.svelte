<script lang="ts">
  import type { ApiKey, Application } from './api';

  interface Props {
    app: Application;
    issuanceBlocked: boolean;
    onissue: (appId: string, name: string) => Promise<boolean>;
    onrevoke: (appId: string, keyId: string) => Promise<void>;
  }

  let { app, issuanceBlocked, onissue, onrevoke }: Props = $props();
  let keyName = $state('');
  let busy = $state(false);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy || issuanceBlocked) return;
    busy = true;
    try {
      if (await onissue(app.id, keyName)) keyName = '';
    } finally {
      busy = false;
    }
  }

  async function revoke(key: ApiKey): Promise<void> {
    if (busy || !window.confirm(`Revoke “${key.name}”? This cannot be undone.`)) return;
    busy = true;
    try {
      await onrevoke(app.id, key.id);
    } finally {
      busy = false;
    }
  }
</script>

<article class="card">
  <h2>{app.name}</h2>
  <code>{app.id}</code>
  <form class="row key-form" onsubmit={submit}>
    <input
      bind:value={keyName}
      placeholder="Client name, for example: My script"
      required
      maxlength={128}
      aria-label="Key name"
    />
    <button type="submit" disabled={busy || issuanceBlocked}>Generate key</button>
  </form>
  <h3>My API keys</h3>
  {#if app.keys.length === 0}
    <p class="empty">You have not generated any API keys for this application.</p>
  {/if}
  <ul>
    {#each app.keys as key (key.id)}
      <li>
        <div>
          <strong>{key.name}</strong>
          <small>{new Date(key.created_at * 1000).toLocaleString('en')} · {key.revoked ? 'Revoked' : 'Active'}</small>
        </div>
        {#if !key.revoked}
          <button type="button" class="danger" disabled={busy} onclick={() => revoke(key)}>Revoke</button>
        {/if}
      </li>
    {/each}
  </ul>
</article>
