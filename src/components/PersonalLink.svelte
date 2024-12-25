<script lang="ts">
	import { type Icon as IconType } from 'lucide-svelte';

	interface PersonalLinkProps {
		Icon: typeof IconType;
		href: string;
		size?: number;
	}

	const { Icon, href, size = 24 }: PersonalLinkProps = $props();
</script>

<a
	{href}
	target="_blank"
	class="border-yellow hover:bg-yellow group/githublink block w-fit rounded-full border-1 p-[10px] transition-colors"
>
	<Icon
		{size}
		strokeWidth={1.5}
		class="group-hover/githublink:stroke-yellow-light transition-colors"
	/>
</a>
