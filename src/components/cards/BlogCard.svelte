<script lang="ts">
	import { Calendar, ChevronRight, Tags } from "lucide-svelte";

	interface BlogCardProps {
		id: number
		title: string
		preview?: string
		tags: string[]
		createdAt: Date
	}

	let { id, title, preview, tags, createdAt }: BlogCardProps = $props()
</script>

<div class="border border-yellow rounded-lg p-5 space-y-2">
	<h3 class="font-semibold text-2xl">
		<a class="hover:text-yellow-light transition-colors" href={`/blog/${id}`}>{title}</a>
	</h3>
	<p class="text-yellow-light">
		{#if preview}
			{preview}...
		{:else}
			No preview for this blog
		{/if}
	</p>
	<div class="flex justify-between">
		<div class="flex space-x-3">
			<span class="flex items-center">
				<Calendar size={20} strokeWidth={2} class="mr-1" />
				<span class="text-yellow-light">{createdAt.toLocaleDateString("en-GB")}</span>
			</span>
			<span class="flex items-center">
				<Tags size={20} strokeWidth={2} class="mr-1" />
				<span class="text-yellow-light">
					{#each tags as tag, index}
						{`${tag}${index == tags.length - 1 ? "" : " | "}`}
					{/each}
				</span>
			</span>
		</div>
		<a class="flex items-center hover:text-yellow-light transition-colors" href={`/blog/${id}`}>
			Read more
			<ChevronRight size={20} strokeWidth={2} class="" />
		</a>
	</div>
</div>
