<script lang="ts">
	import { type Icon as IconType } from 'lucide-svelte'

	interface PersonalLinkProps {
		Icon: typeof IconType
		href: string
		size?: number
	}

	const { Icon, href, size = 24 } : PersonalLinkProps = $props()
</script>

<a href={href} target="_blank" class="block w-fit border-1 border-yellow p-[10px] rounded-full hover:bg-yellow group/githublink transition-colors">
	<Icon size={size} strokeWidth={1.5} class="group-hover/githublink:stroke-yellow-light transition-colors"/>
</a>