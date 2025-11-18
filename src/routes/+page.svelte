<script lang="ts">
	import Footer from '$components/footer/Footer.svelte';
	import Header from '$components/header/Header.svelte';
	import ExperiencesSection from '$components/sections/ExperiencesSection.svelte';
	import InformationSection from '$components/sections/InformationSection.svelte';
	import IntroSection from '$components/sections/IntroSection.svelte';
	import ProjectsSection from '$components/sections/ProjectsSection.svelte';
	import { ChevronsDown } from 'lucide-svelte';
</script>

<svelte:head>
	<title>SteGG</title>
</svelte:head>

<Header />

<main class="mb-20 flex flex-col space-y-20">
	<div class="h-full">
		<IntroSection />
		<div class="mt-16 mb-10 w-full">
			<ChevronsDown size={32} class="mx-auto animate-bounce" />
		</div>
	</div>
	<InformationSection />
	<ExperiencesSection />
	<ProjectsSection />
</main>

<Footer />
