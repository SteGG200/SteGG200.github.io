<script lang="ts">
	import { Status } from '$lib'
	import { Calendar, Tags } from 'lucide-svelte';
	import hljs from 'highlight.js';
	import 'highlight.js/styles/atom-one-dark.min.css'

	let { data } = $props()

	$effect(() => {
		hljs.highlightAll();
	})
</script>

<svelte:head>
	<title>{data.blog?.title}</title>
</svelte:head>

<main class="w-blog mx-auto max-xl:w-5/6 max-md:w-11/12 py-10">
	{#if data.status === Status.SUCCESS && data.blog}
		<section class="border border-yellow rounded-lg p-8 max-md:p-5 space-y-5">
			<h1 class="text-5xl max-md:text-4xl font-bold">{data.blog.title}</h1>
			<div class="flex space-x-4">
				<div class="flex space-x-1 items-center">
					<Calendar />
					<span class="text-yellow-light">{data.blog.createdAt.toLocaleDateString('en-GB')}</span>
				</div>
				<div class="flex space-x-1 items-center">
					<Tags />
					<span class="text-yellow-light">
						{#each data.blog.tags as tag, index}
							{`${tag}${index == data.blog.tags.length - 1 ? "" : " | "}`}
						{/each}
					</span>
				</div>
			</div>
			<div class="markdown-render">
				{@html data.blog.content}
			</div>
		</section>
	{:else}
		<p>{data.error}</p>
	{/if}
</main>
