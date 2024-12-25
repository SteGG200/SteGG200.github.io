<script lang="ts">
	interface ProgressBarProps {
		start: number;
		events: IExperience[];
	}

	const { events, start }: ProgressBarProps = $props();

	const currentYear = new Date().getFullYear();
</script>

<div class="flex w-full flex-col items-center space-y-2">
	<span class="text-lg">{currentYear}</span>
	<div class="after:timeline relative h-[800px] w-full">
		{#each events as event, index}
			<div
				class="border-yellow before:line after:point absolute rounded-lg border-1 p-2 max-md:p-1.5" class:left-event={index % 2 == 0} class:right-event={index % 2 == 1}
				style={`top: calc(${~~(((currentYear - event.year) / (currentYear - start)) * 100)}%)`}
			>
				<h3 class="text-xl font-bold max-md:text-lg">{event.year}</h3>
				<p class="text-yellow-light">{event.description}</p>
			</div>
		{/each}
	</div>
</div>
