<script lang="ts">
	import Footer from '$components/footer/Footer.svelte';
	import Header from '$components/header/Header.svelte';
	import Loading from '$components/Loading.svelte';
	import ExperiencesSection from '$components/sections/ExperiencesSection.svelte';
	import InformationSection from '$components/sections/InformationSection.svelte';
	import IntroSection from '$components/sections/IntroSection.svelte';
	import ProjectsSection from '$components/sections/ProjectsSection.svelte';
	import { ChevronsDown } from 'lucide-svelte';

	let isLoading = $state(true);
	let isFirstVisit = $state(true);

	$effect(() => {
		// Check if user first visit the website
		const firstVisitValue = sessionStorage.getItem('isFirstVisit');
		if (!firstVisitValue) {
			sessionStorage.setItem('isFirstVisit', '1');
		}
		isFirstVisit = firstVisitValue ? false : true;

		isLoading = false;
	});
</script>

<Header />

{#if isLoading}
	<Loading />
{:else}
	<main class="mb-20 flex flex-col space-y-20">
		<div class="h-full">
			<IntroSection {isFirstVisit} />
			<div class="mt-16 mb-10 w-full">
				<ChevronsDown size={32} class="text-yellow mx-auto animate-bounce" />
			</div>
		</div>
		<InformationSection />
		<ExperiencesSection />
		<ProjectsSection />
	</main>
{/if}

<Footer />
