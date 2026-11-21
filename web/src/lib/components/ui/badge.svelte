<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLAttributes } from 'svelte/elements';
  import { tv, type VariantProps } from 'tailwind-variants';
  import { cn } from '../../utils';

  const badgeVariants = tv({
    base: 'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap tabular-nums transition-colors',
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-muted-foreground',
        outline: 'border-border bg-background text-foreground',
        destructive: 'border-destructive/30 bg-destructive-surface text-destructive',
      },
    },
    defaultVariants: {
      variant: 'outline',
    },
  });

  type BadgeVariant = VariantProps<typeof badgeVariants>['variant'];

  interface Props extends HTMLAttributes<HTMLSpanElement> {
    variant?: BadgeVariant;
    class?: string;
    children?: Snippet;
  }

  let { variant = 'outline', class: className = '', children, ...rest }: Props = $props();
</script>

<span class={cn(badgeVariants({ variant }), className)} {...rest}>
  {@render children?.()}
</span>
