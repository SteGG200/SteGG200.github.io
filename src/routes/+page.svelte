<script lang="ts">
	import Header from "$components/header/Header.svelte";
	import Loading from "$components/Loading.svelte";
	import InformationSection from "$components/sections/InformationSection.svelte";
	import IntroSection from "$components/sections/IntroSection.svelte";
	import { ChevronsDown } from "lucide-svelte";

	let isLoading = $state(true);
	let isFirstVisit = $state(true);

	$effect(() => {
		const firstVisitValue = sessionStorage.getItem("isFirstVisit");
		if(!firstVisitValue){
			sessionStorage.setItem("isFirstVisit", "1");
		}
		isFirstVisit = firstVisitValue ? false : true;
		isLoading = false;
	})
</script>

<Header/>

{#if isLoading}
  <Loading/>
{:else}
	<main class="flex flex-col space-y-20">
		<div>
			<IntroSection isFirstVisit={isFirstVisit}/>
			<div class="w-full mt-16">
				<ChevronsDown size={32} class="text-yellow mx-auto animate-bounce"/>
			</div>
		</div>
		<InformationSection/>
	</main>
{/if}