<script lang="ts">
	import Header from "$components/header/Header.svelte";
	import Loading from "$components/Loading.svelte";
	import IntroSection from "$components/sections/IntroSection.svelte";

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
	<IntroSection isFirstVisit={isFirstVisit}/>
{/if}