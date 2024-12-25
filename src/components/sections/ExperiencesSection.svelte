<script lang="ts">
	import LabelSection from '$components/LabelSection.svelte';
	import ProgressBar from '$components/ProgressBar.svelte';

	const experiences: IExperience[] = [
		{ year: 2007, description: 'I was born' },
		{ year: 2020, description: 'I started learning programming' },
		{ year: 2022, description: 'I studied at HSGS' },
		{ year: 2024, description: 'I participated in ICPC national for the first time' }
	];
</script>

<section id="experiences" class="text-yellow mb-35 w-full scroll-mt-30">
	<div class="w-experience-section mx-auto space-y-5 max-xl:w-5/6 max-md:w-11/12">
		<LabelSection>EXPERIENCES</LabelSection>
		<ProgressBar start={2007} events={experiences} />
	</div>
</section>
