<script lang="ts">
	import type { Project } from '$lib/types/project';
	import { Bookmark } from '@lucide/svelte';

	interface Props {
		project: Project;
	}

	let { project }: Props = $props();
</script>

<a
	href={project.url || `https://github.com/${project.repoName}`}
	target="_blank"
	rel="noopener noreferrer"
	class="group relative block overflow-hidden rounded-lg border border-lol-gold/60 bg-lol-bg-dark p-6 transition-all duration-300 hover:border-lol-gold hover:shadow-[0_0_15px_rgba(200,170,110,0.25)]"
>
	<!-- Bookmark Icon & Repo Name Header -->
	<div class="mb-4 flex items-center gap-3">
		<!-- Lucide Bookmark Icon -->
		<div class="text-lol-gold transition-transform group-hover:scale-110">
			<Bookmark class="h-6 w-6 stroke-2" />
		</div>

		<h3
			class="font-['Spiegel'] text-xl font-bold tracking-wide text-lol-gold transition-colors group-hover:text-lol-gold-light"
		>
			{project.repoName}
		</h3>
	</div>

	<!-- Description -->
	<p class="mb-6 font-['Spiegel'] text-base leading-relaxed text-lol-gold-light">
		{project.description}
	</p>

	<!-- Framework / Language Stack -->
	<div class="font-['Spiegel'] text-base text-lol-gold-light">
		{project.techStack}
	</div>
</a>
