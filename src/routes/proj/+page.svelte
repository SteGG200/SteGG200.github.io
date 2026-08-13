<script lang="ts">
	import { projects } from '$lib/data/projects';
	import ProjectCard from '$lib/components/ProjectCard.svelte';
	import Github from '$lib/components/icons/Github.svelte';
</script>

<svelte:head>
	<title>Projects | SteGG200</title>
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
				PROJECTS
			</h1>
			<p class="mt-1 font-['Spiegel'] text-sm text-lol-text-muted">
				Featured open-source repositories and personal builds
			</p>
		</div>
	</div>

	<!-- Projects Grid -->
	<div class="grid grid-cols-1 gap-6 md:grid-cols-2">
		{#each projects as project, i (i)}
			<ProjectCard {project} />
		{/each}
	</div>
</div>
