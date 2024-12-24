<script lang="ts">
	import type { Snippet } from "svelte";

	interface LabelSectionProps {
		children: Snippet
	}

	const { children } : LabelSectionProps = $props()
</script>

<h2 class="text-2xl max-md:text-xl font-semibold">
	{@render children()}
</h2>