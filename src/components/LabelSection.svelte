<script lang="ts">
	import type { Snippet } from 'svelte';

	interface LabelSectionProps {
		children: Snippet;
	}

	const { children }: LabelSectionProps = $props();
</script>

<h2 class="text-2xl font-semibold max-md:text-xl">
	{@render children()}
</h2>
