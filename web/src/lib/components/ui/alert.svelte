<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLAttributes } from 'svelte/elements';
  import { tv, type VariantProps } from 'tailwind-variants';
  import { cn } from '../../utils';

  const alertVariants = tv({
    base: 'flex items-start gap-2.5 rounded-lg border px-3.5 py-3 text-sm',
    variants: {
      variant: {
        default: 'border-border bg-card text-foreground',
        destructive: 'border-destructive/35 bg-destructive-surface text-destructive',
        warning: 'border-warning/35 bg-warning-surface text-foreground',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  });

  type AlertVariant = VariantProps<typeof alertVariants>['variant'];

  interface Props extends HTMLAttributes<HTMLDivElement> {
    variant?: AlertVariant;
    class?: string;
    children?: Snippet;
  }

  let { variant = 'default', class: className = '', children, ...rest }: Props = $props();
</script>

<div class={cn(alertVariants({ variant }), className)} {...rest}>
  {@render children?.()}
</div>
