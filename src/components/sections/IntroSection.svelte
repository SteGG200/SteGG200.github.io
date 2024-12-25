<script lang="ts">
	import PersonalLink from '$components/PersonalLink.svelte';
	import avatar from '$lib/assets/avatar.jpg';
	import { Facebook, Github, Mail } from 'lucide-svelte';

	interface IntroSectionProps {
		isFirstVisit: boolean;
	}

	const descriptions = ['Developer', 'LOL Player', 'Fedora User', 'Music Enjoyer'];

	let currentIndexDescription = $state(0);

	const timeDelay = 5 * 1000;

	let { isFirstVisit }: IntroSectionProps = $props();

	const typingAnimation = (node: HTMLElement, { speed = 1 }: { speed?: number }) => {
		// speed: letters / 0.01 s
		const valid = node.childNodes.length === 1 && node.childNodes[0].nodeType === Node.TEXT_NODE;

		if (!valid) {
			throw new Error(`This transition only works on elements with a single text node child`);
		}

		const text = node.textContent!;
		const duration = text.length / (speed * 0.01);

		return {
			duration,
			tick: (t: number) => {
				const i = ~~(text.length * t);
				node.textContent = text.slice(0, i);
			}
		};
	};

	$effect(() => {
		setInterval(() => {
			currentIndexDescription += 1;
			if (currentIndexDescription >= descriptions.length) currentIndexDescription = 0;
		}, timeDelay);
	});
</script>

<section class="flex w-full max-lg:flex-col max-lg:items-center max-lg:space-y-6">
	<!-- Banner profile -->
	<div class="flex w-1/2 justify-center max-2xl:w-1/3">
		<div
			class="h-banner max-lg:h-banner-lg aspect-banner bg-banner relative bg-cover"
			class:animate-down={isFirstVisit}
		>
			<!-- Avatar -->
			<div class="flex h-[55%] w-full items-end justify-center">
				<div class="relative aspect-square w-[83%]">
					<img
						class="absolute-avatar-center absolute h-[56%] w-[56%] rounded-full"
						src={avatar}
						alt="Avatar"
					/>
					<div class="bg-border-avatar absolute top-0 left-0 h-full w-full bg-cover"></div>
				</div>
			</div>
			<!-- Name -->
			<div class="w-full pt-6">
				<p class="text-yellow-light text-center font-serif text-lg font-bold">Nguyễn Hòa Bình</p>
			</div>
		</div>
	</div>
	<!-- Introduction -->
	<div class="flex w-1/2 items-center max-2xl:w-2/3 max-2xl:justify-center max-lg:w-full">
		<div class="text-yellow flex w-2/3 flex-col justify-center space-y-7 max-lg:w-3/4">
			<h1 class="text-6xl font-semibold max-lg:text-5xl max-sm:text-4xl">
				Hi, It's <span>Binh</span>
			</h1>
			<h3 class="text-4xl font-semibold max-lg:text-3xl max-sm:text-2xl">
				I'm a
				{#each descriptions as description, index}
					{#if index == currentIndexDescription}
						<span class="after:animate-cursor after:border-l-2" in:typingAnimation={{ speed: 1 }}
							>{description}</span
						>
					{/if}
				{/each}
			</h3>
			<p class="text-lg">
				A skilled summoner in the realm of web development, wielding modern technologies to forge
				powerful and elegant digital experiences.
			</p>
			<div class="flex space-x-6">
				<PersonalLink href="https://github.com/SteGG200" Icon={Github} />
				<PersonalLink href="https://www.facebook.com/geor.steven/" Icon={Facebook} />
				<PersonalLink href="mailto:binhbhgl5@gmail.com" Icon={Mail} />
			</div>
		</div>
	</div>
</section>
