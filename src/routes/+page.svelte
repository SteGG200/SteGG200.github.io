<script lang="ts">
	import ProfileCard from '$lib/components/ProfileCard.svelte';
	import Github from '$lib/components/icons/Github.svelte';
	import Facebook from '$lib/components/icons/Facebook.svelte';
	import { Mail } from '@lucide/svelte';
</script>

<svelte:head>
	<title>SteGG200 | Homepage</title>
</svelte:head>

<div class="flex flex-col items-start justify-center gap-12 pb-6 sm:pb-12 lg:flex-row lg:gap-24">
	<!-- Left Side: Profile Banner & Frame Card (stuck flush to navbar) -->
	<div class="flex w-full justify-center lg:w-auto">
		<ProfileCard name="Nguyễn Hòa Bình" />
	</div>

	<!-- Right Side: Hero Greeting & Intro (vertically centered relative to banner) -->
	<div
		class="flex max-w-2xl flex-1 flex-col justify-center space-y-6 self-center py-6 text-center lg:py-12 lg:text-left"
	>
		<div class="space-y-2">
			<span
				class="inline-block rounded border border-lol-blue bg-lol-bg-panel-light px-3 py-1 font-['Beaufort'] text-xs font-bold tracking-widest text-lol-blue uppercase"
			>
				SUMMONER PROFILE
			</span>
			<h1
				class="font-['Beaufort'] text-3xl font-bold tracking-tight text-lol-gold uppercase drop-shadow-[0_0_15px_rgba(200,170,110,0.3)] sm:text-4xl md:text-5xl lg:text-6xl"
			>
				Hi, It's Binh
			</h1>
			<h2
				class="font-['Spiegel'] text-xl font-bold tracking-wide text-lol-gold-light sm:text-2xl lg:text-3xl"
			>
				I'm a Software Developer
			</h2>
		</div>

		<p class="font-['Spiegel'] text-lg leading-relaxed text-lol-text-muted">
			A skilled summoner in the realm of web development, wielding modern technologies to forge
			powerful, high-performance, and elegant digital experiences.
		</p>

		<!-- Social & Quick Action Buttons -->
		<div class="flex flex-wrap items-center justify-center gap-4 pt-4 lg:justify-start">
			<a
				href="https://github.com/SteGG200"
				target="_blank"
				rel="noopener noreferrer"
				class="flex h-12 w-12 items-center justify-center rounded-full border border-lol-gold bg-lol-bg-panel text-lol-gold shadow-md transition-all duration-300 hover:bg-lol-gold hover:text-lol-bg-dark hover:shadow-[0_0_12px_#C8AA6E]"
				title="GitHub Profile"
			>
				<Github strokeWidth="2" class="h-6 w-6" />
			</a>

			<a
				href="https://www.facebook.com/geor.steven/"
				target="_blank"
				rel="noopener noreferrer"
				class="flex h-12 w-12 items-center justify-center rounded-full border border-lol-gold bg-lol-bg-panel text-lol-gold shadow-md transition-all duration-300 hover:bg-lol-gold hover:text-lol-bg-dark hover:shadow-[0_0_12px_#C8AA6E]"
				title="Facebook Profile"
			>
				<Facebook strokeWidth="2" class="h-6 w-6" />
			</a>

			<a
				href="mailto:binhbhgl5@gmail.com"
				class="flex h-12 w-12 items-center justify-center rounded-full border border-lol-gold bg-lol-bg-panel text-lol-gold shadow-md transition-all duration-300 hover:bg-lol-gold hover:text-lol-bg-dark hover:shadow-[0_0_12px_#C8AA6E]"
				title="Send Email"
			>
				<Mail class="h-6 w-6" />
			</a>

			<a href="/info" class="lol-button ml-2"> VIEW FULL STATS </a>
		</div>
	</div>
</div>
