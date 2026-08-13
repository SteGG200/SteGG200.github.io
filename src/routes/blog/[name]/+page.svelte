<script lang="ts">
	import 'highlight.js/styles/atom-one-dark.css';
	import type { PageData } from './$types';
	import { onMount } from 'svelte';
	import { ArrowLeft, Calendar, Hash } from '@lucide/svelte';

	let { data }: { data: PageData } = $props();

	let activeHeadingId = $state<string>('');

	onMount(() => {
		if (data.toc.length === 0) return;

		const observer = new IntersectionObserver(
			(entries) => {
				for (const entry of entries) {
					if (entry.isIntersecting) {
						activeHeadingId = entry.target.id;
					}
				}
			},
			{ rootMargin: '-80px 0px -60% 0px' },
		);

		data.toc.forEach((item) => {
			const el = document.getElementById(item.id);
			if (el) observer.observe(el);
		});

		return () => observer.disconnect();
	});
</script>

<svelte:head>
	<title>{data.blog.title} | SteGG200</title>
</svelte:head>

<div class="space-y-6 py-4">
	<!-- Back Button & Blog Meta Header -->
	<div class="space-y-4 border-b border-lol-gold-dark pb-6">
		<a
			href="/blog"
			class="inline-flex items-center gap-2 font-['Beaufort'] text-xs font-bold tracking-widest text-lol-text-muted uppercase transition-colors hover:text-lol-gold"
		>
			<ArrowLeft class="h-4 w-4" />
			<span>BACK TO ALL BLOGS</span>
		</a>

		<h1
			class="font-['Beaufort'] text-3xl font-bold tracking-wider text-lol-gold uppercase drop-shadow-[0_0_10px_rgba(200,170,110,0.3)] sm:text-5xl"
		>
			{data.blog.title}
		</h1>

		<div class="flex flex-wrap items-center gap-4 font-['Spiegel'] text-sm">
			<span class="inline-flex items-center gap-1 font-bold text-lol-gold-dark">
				<Calendar class="h-4 w-4" />
				{data.blog.createdAt}
			</span>
			<div class="flex flex-wrap items-center gap-2">
				{#each data.blog.tags as tag (tag)}
					<span
						class="inline-flex items-center gap-0.5 rounded border border-lol-blue/40 bg-lol-bg-panel-light px-2 py-0.5 font-['Beaufort'] text-xs font-bold text-lol-blue"
					>
						<Hash class="h-3 w-3" />{tag}
					</span>
				{/each}
			</div>
		</div>
	</div>

	<!-- Main Grid: Article Content + Side TOC -->
	<div class="grid grid-cols-1 gap-8 lg:grid-cols-4">
		<!-- Article Content -->
		<article
			class="prose prose-invert max-w-none space-y-4 font-['Spiegel'] text-lol-gold-light lg:col-span-3"
		>
			{@html data.html}
		</article>

		<!-- Table of Contents Side Panel -->
		{#if data.toc.length > 0}
			<aside class="lg:col-span-1">
				<div class="lol-panel sticky top-24 space-y-3 rounded p-5">
					<h3
						class="border-b border-lol-gold-dark/50 pb-2 font-['Beaufort'] text-xs font-bold tracking-widest text-lol-gold uppercase"
					>
						TABLE OF CONTENTS
					</h3>

					<nav class="max-h-[70vh] space-y-1 overflow-y-auto text-sm">
						{#each data.toc as item (item.id)}
							<a
								href={`#${item.id}`}
								class="line-clamp-1 block rounded px-2 py-1 font-['Spiegel'] text-xs transition-colors
									{item.level === 2 ? 'pl-3' : item.level === 3 ? 'pl-6' : ''}
									{activeHeadingId === item.id
									? 'border-l-2 border-lol-gold bg-lol-bg-panel-light font-bold text-lol-gold'
									: 'text-lol-text-muted hover:text-lol-gold-light'}"
							>
								{item.text}
							</a>
						{/each}
					</nav>
				</div>
			</aside>
		{/if}
	</div>
</div>

<style>
	/* Custom Markdown Typography inside Article */
	:global(article h1) {
		font-family: 'Beaufort', serif;
		color: #c8aa6e;
		font-size: 1.875rem;
		font-weight: 700;
		margin-top: 2rem;
		margin-bottom: 1rem;
		border-bottom: 1px solid rgba(120, 90, 40, 0.4);
		padding-bottom: 0.5rem;
	}

	:global(article h2) {
		font-family: 'Beaufort', serif;
		color: #f0e6d2;
		font-size: 1.5rem;
		font-weight: 700;
		margin-top: 1.75rem;
		margin-bottom: 0.75rem;
	}

	:global(article h3) {
		font-family: 'Beaufort', serif;
		color: #c8aa6e;
		font-size: 1.25rem;
		font-weight: 700;
		margin-top: 1.5rem;
		margin-bottom: 0.5rem;
	}

	:global(article p) {
		line-height: 1.75;
		margin-bottom: 1.25rem;
		color: #f0e6d2;
	}

	:global(article ul) {
		list-style-type: disc;
		padding-left: 1.5rem;
		margin-bottom: 1.25rem;
	}

	:global(article li) {
		margin-bottom: 0.5rem;
		color: #a09b8c;
	}

	:global(article a) {
		color: #0397ab;
		text-decoration: underline;
	}

	:global(article a:hover) {
		color: #c8aa6e;
	}

	:global(article :not(pre) > code) {
		background-color: rgba(10, 20, 40, 0.8);
		color: #c8aa6e;
		border: 1px solid #463714;
		border-radius: 0.25rem;
		padding: 0.15rem 0.4rem;
		font-family: monospace;
		font-size: 0.825rem;
	}

	:global(article pre) {
		overflow-x: auto;
		border-radius: 0.375rem;
		padding: 1rem;
		background-color: #0a1428;
		border: 1px solid #785a28;
	}

	:global(article table) {
		display: block;
		overflow-x: auto;
		width: 100%;
	}
</style>
