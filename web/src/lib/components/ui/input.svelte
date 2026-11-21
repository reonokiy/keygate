<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  import { cn } from '../../utils';

  interface Props extends Omit<HTMLInputAttributes, 'value'> {
    value?: string;
    ref?: HTMLInputElement;
    class?: string;
  }

  let { value = $bindable(''), ref = $bindable(), class: className = '', ...rest }: Props = $props();
</script>

<input
  bind:this={ref}
  bind:value
  class={cn(
    'flex h-9 w-full min-w-0 rounded-md border border-input bg-background px-3 py-1 text-sm text-foreground shadow-xs transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30 disabled:cursor-not-allowed disabled:opacity-50',
    className,
  )}
  {...rest}
/>
