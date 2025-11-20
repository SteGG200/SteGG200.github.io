<script lang="ts">
	const descriptions = ['Software Developer', 'LOL Player', 'Arch User', 'Music Enjoyer'];

	let currentIndexDescription = $state(-1);
	let timeDelay = $state(0);

	const typingAnimation = (node: HTMLElement, { speed = 1 }: { speed?: number }) => {
		// speed: letters / 0.01 s
		const valid = node.childNodes.length === 1 && node.childNodes[0].nodeType === Node.TEXT_NODE;

		if (!valid) {
			throw new Error(`This transition only works on elements with a single text node child`);
		}

		const typingEasing = 0.2;
		const text = node.textContent ?? '';
		const typingTime = text.length / (speed * 0.01);
		const duration = typingTime * 2 + (1 - typingEasing * 2) * typingTime;
		timeDelay = duration;

		return {
			duration,
			tick: (t: number, u: number) => {
				if (t < typingEasing) {
					t /= typingEasing;
					const i = ~~(text.length * t);
					node.textContent = text.slice(0, i);
				} else if (u < typingEasing) {
					u /= typingEasing;
					const i = ~~(text.length * u);
					node.textContent = text.slice(0, i);
				} else {
					node.textContent = text;
				}
			}
		};
	};

	$effect(() => {
		const id = setInterval(() => {
			currentIndexDescription = (currentIndexDescription + 1) % descriptions.length;
		}, timeDelay);

		return () => {
			clearInterval(id);
		};
	});
</script>

<h3 class="text-4xl font-semibold max-lg:text-3xl max-sm:text-2xl">
	I'm a
	{#each descriptions as description, index (index)}
		{#if index == currentIndexDescription}
			<span class="after:animate-cursor after:border-l-2" in:typingAnimation={{ speed: 0.5 }}
				>{description}</span
			>
		{/if}
	{/each}
</h3>
