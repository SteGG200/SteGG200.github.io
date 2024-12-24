<script lang="ts">
	import PersonalLink from '$components/PersonalLink.svelte';
	import avatar from '$lib/assets/avatar.jpg'
	import { Facebook, Github, Mail } from 'lucide-svelte'

	interface IntroSectionProps {
		isFirstVisit: boolean
	}

	const descriptions = [
		"Developer",
		"LOL Player",
		"Fedora User",
		"Music Enjoyer"
	]
	
	let currentIndexDescription = $state(0)

	const timeDelay = 5 * 1000

	let { isFirstVisit }: IntroSectionProps = $props()

	const typingAnimation = (node: HTMLElement, { speed = 1 }: { speed?: number }) => { // speed: letters / 0.01 s
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
	}

	$effect(() => {
		setInterval(() => {
			currentIndexDescription += 1
			if(currentIndexDescription >= descriptions.length) currentIndexDescription = 0;
		}, timeDelay)
	})
</script>

<section class="w-full flex max-lg:flex-col max-lg:items-center max-lg:space-y-6">
	<!-- Banner profile -->
	<div class="w-1/2 max-2xl:w-1/3 flex justify-center">
		<div class="relative h-banner max-lg:h-banner-lg aspect-banner bg-banner bg-cover" class:animate-down={isFirstVisit}>
			<!-- Avatar -->
			<div class="w-full h-[55%] flex justify-center items-end">
				<div class="w-[83%] aspect-square relative">
					<img class="absolute absolute-avatar-center rounded-full w-[56%] h-[56%]" src={avatar} alt="Avatar">
					<div class="absolute top-0 left-0 w-full h-full bg-border-avatar bg-cover"></div>
				</div>
			</div>
			<!-- Name -->
			<div class="w-full pt-6">
				<p class="font-serif text-lightyellow text-lg text-center font-bold">Nguyễn Hòa Bình</p>
			</div>
		</div>
	</div>
	<!-- Introduction -->
	<div class="w-1/2 max-2xl:w-2/3 max-lg:w-full flex max-2xl:justify-center items-center">
		<div class="w-2/3 max-lg:w-3/4 text-yellow flex flex-col justify-center space-y-7">
			<h1 class="text-6xl max-lg:text-5xl max-sm:text-4xl font-semibold">Hi, It's <span>Binh</span></h1>
			<h3 class="text-4xl max-lg:text-3xl max-sm:text-2xl font-semibold">
				I'm a 
				{#each descriptions as description, index}
					{#if index == currentIndexDescription}
						<span class="after:border-l-2 after:animate-cursor" in:typingAnimation={{speed: 1}}>{description}</span>
					{/if}
				{/each}
			</h3>
			<p class="text-lg">A skilled summoner in the realm of web development, wielding modern technologies to forge powerful and elegant digital experiences.</p>
			<div class="flex space-x-6">
				<PersonalLink href="https://github.com/SteGG200" Icon={Github}/>
				<PersonalLink href="https://www.facebook.com/geor.steven/" Icon={Facebook}/>
				<PersonalLink href="mailto:binhbhgl5@gmail.com" Icon={Mail}/>
			</div>
		</div>
	</div>
</section>