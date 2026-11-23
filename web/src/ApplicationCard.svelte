<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import Copy from '@lucide/svelte/icons/copy';
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Plus from '@lucide/svelte/icons/plus';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import Search from '@lucide/svelte/icons/search';
  import type { ApiKey, Application } from './api';
  import Badge from './lib/components/ui/badge.svelte';
  import Button from './lib/components/ui/button.svelte';
  import Input from './lib/components/ui/input.svelte';

  type StatusFilter = 'all' | 'active' | 'revoked';

  interface Props {
    app: Application;
    issuanceBlocked: boolean;
    revokingKeyId: string | null;
    recentKeyId?: string | null;
    onopenissue: (app: Application) => void;
    onrequestrevoke: (app: Application, key: ApiKey) => void;
  }

  let {
    app,
    issuanceBlocked,
    revokingKeyId,
    recentKeyId = null,
    onopenissue,
    onrequestrevoke,
  }: Props = $props();

  let statusFilter = $state<StatusFilter>('all');
  let searchQuery = $state('');
  let copiedId = $state(false);

  const shortDateFormat = new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  let activeCount = $derived(app.keys.filter((key) => !key.revoked).length);
  let revokedCount = $derived(app.keys.filter((key) => key.revoked).length);

  let filteredKeys = $derived.by(() => {
    const query = searchQuery.trim().toLowerCase();
    return app.keys.filter((key) => {
      if (statusFilter === 'active' && key.revoked) return false;
      if (statusFilter === 'revoked' && !key.revoked) return false;
      if (query && !key.name.toLowerCase().includes(query)) return false;
      return true;
    });
  });

  let isFiltered = $derived(statusFilter !== 'all' || searchQuery.trim().length > 0);

  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    const currentId = app.id;
    void currentId;
    statusFilter = 'all';
    searchQuery = '';
    copiedId = false;
    return () => {
      if (copyTimer !== undefined) {
        clearTimeout(copyTimer);
        copyTimer = undefined;
      }
    };
  });

  function formatShortDate(unixSeconds: number): string {
    return shortDateFormat.format(new Date(unixSeconds * 1000));
  }

  function formatFullDate(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleString('en');
  }

  function resetFilters(): void {
    statusFilter = 'all';
    searchQuery = '';
  }

  async function copyApplicationId(): Promise<void> {
    try {
      await navigator.clipboard.writeText(app.id);
      copiedId = true;
      if (copyTimer !== undefined) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => {
        copiedId = false;
      }, 1500);
    } catch {
      // Clipboard API unavailable on insecure origins; ignore silently.
    }
  }
</script>

<div class="flex flex-col">
  <div class="flex flex-col gap-4 pb-6 sm:flex-row sm:items-start sm:justify-between">
    <div class="min-w-0 space-y-1">
      <h2 class="text-2xl font-semibold tracking-tight text-foreground">{app.name}</h2>
      <div class="flex items-center gap-1 text-xs text-muted-foreground">
        <code class="truncate font-mono">{app.id}</code>
        <Button
          variant="ghost"
          size="iconSm"
          class="text-muted-foreground hover:text-foreground"
          onclick={copyApplicationId}
          aria-label={copiedId ? 'Copied application ID' : 'Copy application ID'}
          title={copiedId ? 'Copied' : 'Copy application ID'}
        >
          {#if copiedId}
            <Check class="kg-pop-in size-3.5 text-success" />
          {:else}
            <Copy class="size-3.5" />
          {/if}
        </Button>
      </div>
    </div>

    <Button
      disabled={issuanceBlocked}
      onclick={() => onopenissue(app)}
      class="w-full sm:w-auto"
    >
      <Plus class="size-4" />
      Generate key
    </Button>
  </div>

  {#if app.keys.length === 0}
    <div class="kg-panel-in flex flex-col items-center justify-center rounded-lg border border-dashed border-border px-6 py-14 text-center">
      <div
        class="mb-3 flex size-10 items-center justify-center rounded-lg border border-border bg-muted/50 text-muted-foreground"
        aria-hidden="true"
      >
        <KeyRound class="size-4" />
      </div>
      <h3 class="text-sm font-medium text-foreground">No API keys</h3>
      <p class="mt-1 max-w-sm text-sm text-muted-foreground">
        You have not generated any API keys for this application.
      </p>
      <Button
        variant="outline"
        size="sm"
        class="mt-4"
        disabled={issuanceBlocked}
        onclick={() => onopenissue(app)}
      >
        <Plus class="size-3.5" />
        Create your first key
      </Button>
    </div>
  {:else}
    <div class="flex flex-col gap-2.5 pb-4 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex flex-1 items-center gap-2">
        <div class="relative w-full sm:max-w-64">
          <Search
            class="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            type="search"
            bind:value={searchQuery}
            placeholder="Filter keys..."
            aria-label="Search keys"
            class="h-8 pl-8 text-xs shadow-none"
          />
        </div>
        {#if isFiltered}
          <Button
            variant="ghost"
            size="sm"
            onclick={resetFilters}
            class="kg-fade-in text-muted-foreground"
          >
            Reset
            <RotateCcw class="size-3.5" />
          </Button>
        {/if}
      </div>

      <div
        class="inline-flex h-8 w-fit items-center rounded-md bg-muted p-0.5 text-muted-foreground"
        role="tablist"
        aria-label="Filter keys by status"
      >
        <button
          type="button"
          role="tab"
          aria-selected={statusFilter === 'all'}
          class="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-sm px-2.5 text-xs font-medium transition-all duration-150 {statusFilter === 'all'
            ? 'bg-background text-foreground shadow-xs'
            : 'hover:text-foreground'}"
          onclick={() => (statusFilter = 'all')}
        >
          <span>All</span>
          <span class="tabular-nums opacity-65">{app.keys.length}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={statusFilter === 'active'}
          class="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-sm px-2.5 text-xs font-medium transition-all duration-150 {statusFilter === 'active'
            ? 'bg-background text-foreground shadow-xs'
            : 'hover:text-foreground'}"
          onclick={() => (statusFilter = 'active')}
        >
          <span>Active</span>
          <span class="tabular-nums opacity-65">{activeCount}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={statusFilter === 'revoked'}
          class="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-sm px-2.5 text-xs font-medium transition-all duration-150 {statusFilter === 'revoked'
            ? 'bg-background text-foreground shadow-xs'
            : 'hover:text-foreground'}"
          onclick={() => (statusFilter = 'revoked')}
        >
          <span>Revoked</span>
          <span class="tabular-nums opacity-65">{revokedCount}</span>
        </button>
      </div>
    </div>

    <div class="overflow-hidden rounded-md border border-border">
      <div class="w-full overflow-x-auto">
        <table class="w-full caption-bottom border-collapse text-sm">
          <thead>
            <tr class="border-b border-border bg-muted/40 transition-colors">
              <th class="h-10 px-4 text-left align-middle text-xs font-medium text-muted-foreground">
                Name
              </th>
              <th class="hidden h-10 px-4 text-left align-middle text-xs font-medium text-muted-foreground sm:table-cell">
                Created
              </th>
              <th class="h-10 px-4 text-left align-middle text-xs font-medium text-muted-foreground">
                Status
              </th>
              <th class="h-10 px-4 text-right align-middle text-xs font-medium text-muted-foreground">
                <span class="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border">
            {#if filteredKeys.length === 0}
              <tr class="kg-fade-in">
                <td colspan="4" class="h-24 px-4 text-center text-sm text-muted-foreground">
                  No keys match your current filter.
                </td>
              </tr>
            {:else}
              {#each filteredKeys as key (key.id)}
                <tr
                  class="transition-colors duration-150 hover:bg-muted/40 {recentKeyId === key.id
                    ? 'kg-row-highlight'
                    : 'kg-row-in'}"
                >
                  <td class="px-4 py-3 align-middle">
                    <div class="min-w-0">
                      <strong
                        class="block break-words font-medium transition-colors duration-200 {key.revoked
                          ? 'text-muted-foreground line-through decoration-muted-foreground/50'
                          : 'text-foreground'}"
                      >
                        {key.name}
                      </strong>
                      <span
                        class="mt-0.5 block text-xs text-muted-foreground tabular-nums sm:hidden"
                        title={formatFullDate(key.created_at)}
                      >
                        {formatShortDate(key.created_at)}
                      </span>
                    </div>
                  </td>
                  <td
                    class="hidden whitespace-nowrap px-4 py-3 align-middle text-xs text-muted-foreground tabular-nums sm:table-cell"
                    title={formatFullDate(key.created_at)}
                  >
                    {formatShortDate(key.created_at)}
                  </td>
                  <td class="whitespace-nowrap px-4 py-3 align-middle">
                    {#if key.revoked}
                      <Badge variant="secondary">Revoked</Badge>
                    {:else}
                      <Badge variant="outline">
                        <span class="size-1.5 rounded-full bg-success" aria-hidden="true"></span>
                        Active
                      </Badge>
                    {/if}
                  </td>
                  <td class="whitespace-nowrap px-4 py-3 text-right align-middle">
                    {#if !key.revoked}
                      <Button
                        variant="ghostDestructive"
                        size="xs"
                        disabled={revokingKeyId === key.id}
                        onclick={() => onrequestrevoke(app, key)}
                      >
                        Revoke
                      </Button>
                    {/if}
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  {/if}

  <footer class="mt-3 flex flex-col gap-1 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
    {#if app.keys.length > 0}
      <span class="tabular-nums">
        {filteredKeys.length} of {app.keys.length} {app.keys.length === 1 ? 'key' : 'keys'}
      </span>
    {/if}
    <span>
      Revocations usually take effect within 30 seconds, depending on your administrator's cache settings.
    </span>
  </footer>
</div>
