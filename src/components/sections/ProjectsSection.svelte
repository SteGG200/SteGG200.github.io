<script lang="ts">
	import LabelSection from '$components/LabelSection.svelte';
	import ProjectCard from '$components/ProjectCard.svelte';

	const repositories: IRepository[] = [
		{
			fullName: 'SteGG200/storage',
			description: 'A self-hosted file storage server.',
			language: 'Go + Nextjs'
		},
		{
			fullName: 'SteGG200/gomoku-onl',
			description: 'A simple gomoku online game',
			language: 'Expressjs + Nextjs'
		},
		{
			fullName: 'dta1tin22/thestorkjournal',
			description: 'A News Website',
			language: 'Fastify + Svelte'
		},
		{
			fullName: 'dta1tin22/stormtracker',
			description: 'A website tracking all storms around the world',
			language: 'Expressjs + Svelte'
		}
	];
</script>

<section id="projects" class="w-full">
	<div class="w-project-section mx-auto space-y-4 max-xl:w-5/6 max-md:w-11/12">
		<LabelSection>MY PROJECTS</LabelSection>
		<div class="grid w-full grid-cols-3 gap-6 max-xl:grid-cols-2 max-md:grid-cols-1">
			{#each repositories as repository}
				<ProjectCard {repository} />
			{/each}
		</div>
	</div>
</section>
