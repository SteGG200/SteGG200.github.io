<script lang="ts">
	import LabelSection from "$components/LabelSection.svelte";
	import ProjectCard from "$components/ProjectCard.svelte";

	const repositories : IRepository[] = [
		{
			fullName: 'SteGG200/tester_interactive',
			description: 'Tester CLI for interactive problem',
			language: 'Python'
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
	]
</script>

<section class="w-full text-yellow">
	<div class="w-project-section max-xl:w-5/6 max-md:w-11/12 mx-auto space-y-4">
		<LabelSection>MY PROJECTS</LabelSection>
		<div class="w-full grid grid-cols-3 max-xl:grid-cols-2 max-md:grid-cols-1 gap-6">
			{#each repositories as repository}
				<ProjectCard repository={repository}/>
			{/each}
		</div>
	</div>
</section>
