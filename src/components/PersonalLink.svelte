<script lang="ts">
	import { type Icon as IconType } from 'lucide-svelte';
	import type { Component } from 'svelte';

	interface PersonalLinkProps {
		Icon: typeof IconType | Component<IconCustomProps>;
		href: string;
		size?: number;
	}

	const { Icon, href, size = 24 }: PersonalLinkProps = $props();
</script>

<a
	{href}
	target="_blank"
	class="border-yellow hover:bg-yellow group/githublink block w-fit rounded-full border p-[10px] transition-colors"
>
	<Icon
		{size}
		strokeWidth={1.5}
		class="group-hover/githublink:stroke-yellow-light transition-colors"
	/>
</a>
