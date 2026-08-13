<script lang="ts">
	import { experiences } from '$lib/data/experiences';
	import { Gem, Trophy } from '@lucide/svelte';
	function sortKey(period: string): number {
		if (/present/i.test(period)) return Infinity;
		const years = period.match(/\d{4}/g);
		if (!years) return 0;
		return Math.max(...years.map(Number));
	}

	const sorted = $derived([...experiences].sort((a, b) => sortKey(b.period) - sortKey(a.period)));
</script>

<svelte:head>
	<title>Experiences | SteGG200</title>
</svelte:head>

<div class="space-y-8 py-4">
	<!-- LOL Challenges Top Banner -->
	<div
		class="lol-panel flex flex-col items-center gap-4 rounded border-l-4 border-l-lol-gold p-4 text-center sm:flex-row sm:items-start sm:gap-6 sm:p-6 sm:text-left"
	>
		<!-- Rank Emblem -->
		<div
			class="relative flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-full border-2 border-lol-gold bg-lol-bg-panel shadow-[0_0_15px_rgba(200,170,110,0.3)] sm:h-20 sm:w-20"
		>
			<Gem class="h-8 w-8 text-lol-blue sm:h-10 sm:w-10" />
		</div>

		<div>
			<h1
				class="font-['Beaufort'] text-2xl font-bold tracking-wider text-lol-gold uppercase sm:text-3xl"
			>
				EXPERTISE & CHALLENGES
			</h1>
			<p class="mt-1 font-['Spiegel'] text-sm text-lol-text-muted">
				Track recorded progress, education, activities, and career milestones.
			</p>
		</div>
	</div>

	<!-- Content Area -->
	{#if sorted.length === 0}
		<!-- Empty State -->
		<div
			class="lol-panel mx-auto my-8 max-w-2xl space-y-4 rounded border border-lol-gold-dark/50 p-12 text-center"
		>
			<div
				class="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-lol-gold-dark bg-lol-bg-panel text-lol-gold-dark"
			>
				<Trophy class="h-8 w-8" />
			</div>
			<h2 class="font-['Beaufort'] text-2xl font-bold tracking-wider text-lol-gold uppercase">
				NO EXPERIENCES LOGGED YET
			</h2>
			<p class="mx-auto max-w-md font-['Spiegel'] text-sm leading-relaxed text-lol-text-muted">
				The summoner has not added any experiences to the database yet. Update <code
					class="rounded border border-lol-border-gold bg-lol-bg-dark px-2 py-0.5 text-lol-gold"
					>src/lib/data/experiences.ts</code
				> to display your milestones here!
			</p>
		</div>
	{:else}
		<div class="relative ml-4 pl-8">
			<!-- Timeline vertical line: starts at y=6px (middle of top dot) and passes through x=6px (center of dots) -->
			<div class="absolute top-1.5 bottom-3 left-1.25 w-0.5 bg-lol-gold-dark"></div>

			{#each sorted as exp, i (i)}
				<div class="group relative pb-8 last:pb-0">
					<!-- Timeline dot: x=0..12px (center 6px), y=0..12px (center 6px) -->
					<div
						class="absolute top-0 -left-8 h-3 w-3 rounded-full border-2 border-lol-gold bg-lol-bg-panel transition-shadow group-hover:shadow-[0_0_8px_rgba(200,170,110,0.5)]"
					></div>

					<!-- Card -->
					<div
						class="lol-panel rounded border border-lol-gold-dark p-5 transition-colors group-hover:border-lol-gold"
					>
						<p class="font-['Beaufort'] text-base font-bold tracking-wider text-lol-gold">
							{exp.period}
						</p>
						<p class="mt-2 font-['Spiegel'] text-base leading-relaxed text-lol-text-muted">
							{exp.description}
						</p>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>
