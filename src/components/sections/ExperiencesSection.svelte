<script lang="ts">
	import ProgressBar from "$components/ProgressBar.svelte";

	const experiences : IExperience[] = [
		{year: 2007, description: "I was born"},
		{year: 2020, description: "I started learning programming"},
		{year: 2022, description: "I studied at HSGS"},
		{year: 2024, description: "I participated in ICPC national for the first time"}
	]
</script>

<section id="experiences" class="w-full text-yellow">
	<div class="w-5/6 max-md:w-11/12 mx-auto space-y-5">
		<h3 class="text-2xl max-md:text-xl font-semibold">EXPERIENCES</h3>
		<ProgressBar start={2007} events={experiences} />
	</div>
</section>