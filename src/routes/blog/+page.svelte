<script lang="ts">
	import type { PageData } from './$types';
	import { Search, Calendar } from '@lucide/svelte';

	let { data }: { data: PageData } = $props();

	let searchQuery = $state('');
	let selectedTags = $state<Set<string>>(new Set());
	let currentPage = $state(1);
	const ITEMS_PER_PAGE = 10;

	// Extract all unique tags
	const allTags = $derived(Array.from(new Set(data.blogs.flatMap((b) => b.tags))));

	// Filter blogs by search term and selected tag
	const filteredBlogs = $derived(
		data.blogs.filter((blog) => {
			const matchesSearch =
				searchQuery === '' ||
				blog.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
				blog.preview.toLowerCase().includes(searchQuery.toLowerCase());
			const matchesTag =
				selectedTags.size === 0 || [...selectedTags].every((t) => blog.tags.includes(t));
			return matchesSearch && matchesTag;
		}),
	);

	// Pagination math
	const totalPages = $derived(Math.ceil(filteredBlogs.length / ITEMS_PER_PAGE) || 1);
	const paginatedBlogs = $derived(
		filteredBlogs.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE),
	);

	function toggleTag(tag: string) {
		const next = new Set(selectedTags);
		if (next.has(tag)) {
			next.delete(tag);
		} else {
			next.add(tag);
		}
		selectedTags = next;
		currentPage = 1;
	}
</script>

<svelte:head>
	<title>Blogs | SteGG200</title>
</svelte:head>

<div class="space-y-8 py-4">
	<!-- Page Header -->
	<div
		class="flex flex-col justify-between gap-4 border-b border-lol-gold-dark pb-4 sm:flex-row sm:items-center"
	>
		<div>
			<h1
				class="font-['Beaufort'] text-3xl font-bold tracking-wider text-lol-gold uppercase drop-shadow-[0_0_10px_rgba(200,170,110,0.3)] sm:text-4xl"
			>
				SUMMONER'S CHRONICLES
			</h1>
			<p class="mt-1 font-['Spiegel'] text-sm text-lol-text-muted">
				Articles, dev notes, and technical writeups
			</p>
		</div>

		<!-- Search Input -->
		<div class="relative w-full sm:w-72">
			<input
				type="text"
				bind:value={searchQuery}
				oninput={() => (currentPage = 1)}
				placeholder="Search blog by title..."
				class="w-full rounded border border-lol-gold-dark bg-lol-bg-dark px-4 py-2 pl-9 font-['Spiegel'] text-sm text-lol-gold-light transition-colors outline-none"
			/>
			<Search class="absolute top-3 left-3 h-4 w-4 text-lol-gold-dark" />
		</div>
	</div>

	<!-- Tag Filter Chips -->
	{#if allTags.length > 0}
		<div class="flex flex-wrap items-center gap-2">
			<span
				class="mr-2 font-['Beaufort'] text-xs font-bold tracking-widest text-lol-gold-dark uppercase"
			>
				TAGS:
			</span>
			<button
				onclick={() => {
					selectedTags = new Set();
					currentPage = 1;
				}}
				class="rounded px-3 py-1 font-['Beaufort'] text-xs font-bold tracking-wider uppercase transition-all
					{selectedTags.size === 0
					? 'bg-lol-gold text-lol-bg-dark shadow-[0_0_8px_#C8AA6E]'
					: 'border border-lol-gold-dark bg-lol-bg-panel text-lol-text-muted hover:text-lol-gold-light'}"
			>
				ALL
			</button>
			{#each allTags as tag (tag)}
				<button
					onclick={() => toggleTag(tag)}
					class="rounded px-3 py-1 font-['Beaufort'] text-xs font-bold tracking-wider uppercase transition-all
						{selectedTags.has(tag)
						? 'bg-lol-blue text-lol-bg-dark shadow-[0_0_8px_#0397AB]'
						: 'border border-lol-gold-dark bg-lol-bg-panel text-lol-text-muted hover:text-lol-gold-light'}"
				>
					#{tag}
				</button>
			{/each}
		</div>
	{/if}

	<!-- Blog Cards List -->
	{#if paginatedBlogs.length === 0}
		<div class="lol-panel my-8 rounded border border-lol-gold-dark/50 p-12 text-center">
			<h2 class="font-['Beaufort'] text-2xl font-bold text-lol-gold uppercase">NO BLOGS MATCHED</h2>
			<p class="mt-2 font-['Spiegel'] text-sm text-lol-text-muted">
				Try clearing your search or selecting a different tag filter.
			</p>
		</div>
	{:else}
		<div class="space-y-4">
			{#each paginatedBlogs as blog (blog.slug)}
				<a
					href="/blog/{blog.slug}"
					class="lol-panel group relative block overflow-hidden rounded p-6 transition-all duration-300 hover:border-lol-gold"
				>
					<!-- Top Accent -->
					<div
						class="absolute top-0 left-0 h-full w-1 bg-lol-gold-dark transition-colors group-hover:bg-lol-gold"
					></div>

					<div class="flex flex-col justify-between gap-4 md:flex-row md:items-center">
						<div class="flex-1 space-y-2">
							<div class="flex items-center gap-3">
								<h2
									class="font-['Beaufort'] text-2xl font-bold text-lol-gold-light transition-colors group-hover:text-lol-gold"
								>
									{blog.title}
								</h2>
							</div>

							<p class="line-clamp-2 font-['Spiegel'] text-sm leading-relaxed text-lol-text-muted">
								{blog.preview}
							</p>

							<div class="flex flex-wrap items-center gap-3 pt-1">
								<span
									class="inline-flex items-center gap-1 font-['Spiegel'] text-xs font-bold text-lol-gold-dark"
								>
									<Calendar class="inline h-3.5 w-3.5" />
									{blog.createdAt}
								</span>
								<div class="flex flex-wrap items-center gap-1.5">
									{#each blog.tags as tag (tag)}
										<span
											class="rounded border border-lol-blue/40 bg-lol-bg-panel-light px-2 py-0.5 font-['Beaufort'] text-[10px] font-bold text-lol-blue"
										>
											{tag}
										</span>
									{/each}
								</div>
							</div>
						</div>

						<div
							class="flex shrink-0 items-center font-['Beaufort'] text-xs font-bold tracking-widest text-lol-gold transition-transform group-hover:translate-x-1"
						>
							READ ARTICLE →
						</div>
					</div>
				</a>
			{/each}
		</div>

		<!-- Pagination Controls (Max 10 per page) -->
		{#if totalPages > 1}
			<div class="flex items-center justify-center gap-2 pt-6">
				<button
					disabled={currentPage === 1}
					onclick={() => (currentPage -= 1)}
					class="lol-button px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40"
				>
					PREV
				</button>
				<span class="px-3 font-['Beaufort'] text-sm font-bold text-lol-gold">
					PAGE {currentPage} OF {totalPages}
				</span>
				<button
					disabled={currentPage === totalPages}
					onclick={() => (currentPage += 1)}
					class="lol-button px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40"
				>
					NEXT
				</button>
			</div>
		{/if}
	{/if}
</div>
