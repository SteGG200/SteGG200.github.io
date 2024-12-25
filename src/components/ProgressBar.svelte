<script lang="ts">
	interface ProgressBarProps{
		start: number;
		events: IExperience[]
	}

	const { events, start } : ProgressBarProps = $props()

	const currentYear = new Date().getFullYear()
</script>

<div class="w-full flex flex-col items-center space-y-2">
	<span class="text-lg">{currentYear}</span>
	<div class="relative w-full h-[800px] after:timeline">
		{#each events as event, index}
			<div class="absolute border-1 border-yellow rounded-lg p-2 max-md:p-1.5 before:line after:point" class:left-event={index % 2 == 0} class:right-event={index % 2 == 1} style={`top: calc(${~~((currentYear - event.year) / (currentYear - start) * 100)}%)`}>
				<h3 class="text-xl max-md:text-lg font-bold">{event.year}</h3>
				<p class="text-yellow-light">{event.description}</p>
			</div>
		{/each}
	</div>
</div>