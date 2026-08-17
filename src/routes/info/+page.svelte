<script lang="ts">
	import { Gamepad2, User, Calendar, MapPin, Briefcase, Zap, ShieldAlert } from '@lucide/svelte';

	const currentYear = new Date().getFullYear();
	const userAge = currentYear - 2007;

	const infoItems = [
		{ label: 'SUMMONER NAME', value: 'SteGG200', icon: Gamepad2 },
		{ label: 'REAL NAME', value: 'Nguyễn Hòa Bình', icon: User },
		{ label: 'LEVEL / AGE', value: `LVL ${userAge} (${userAge} years old)`, icon: ShieldAlert },
		{ label: 'BIRTHDAY', value: '2007-10-20', icon: Calendar },
		{ label: 'LOCATION', value: 'Hà Nội, Việt Nam', icon: MapPin },
		{ label: 'CURRENT JOB', value: 'Software Developer / Student', icon: Briefcase },
		{ label: 'HOBBIES', value: 'League of Legends, Coding, Open Source, Gaming', icon: Zap },
	];
</script>

<svelte:head>
	<title>Information | SteGG200</title>
</svelte:head>

<div class="mx-auto max-w-4xl space-y-8 py-4">
	<!-- Page Header -->
	<div
		class="flex flex-col gap-3 border-b border-lol-gold-dark pb-4 sm:flex-row sm:items-center sm:justify-between"
	>
		<div>
			<h1
				class="font-['Beaufort'] text-3xl font-bold tracking-wider text-lol-gold uppercase drop-shadow-[0_0_10px_rgba(200,170,110,0.3)] sm:text-4xl"
			>
				SUMMONER INFORMATION
			</h1>
			<p class="mt-1 font-['Spiegel'] text-sm text-lol-text-muted">
				Overview of basic profile attributes and characteristics
			</p>
		</div>
		<div
			class="self-start rounded border border-lol-blue bg-lol-bg-panel-light px-3 py-1 font-['Beaufort'] text-xs font-bold text-lol-blue sm:self-auto"
		>
			INFO PANEL
		</div>
	</div>

	<!-- Info Grid -->
	<div class="grid grid-cols-1 gap-6 md:grid-cols-2">
		{#each infoItems as item (item.label)}
			<div
				class="lol-panel group relative overflow-hidden rounded p-5 transition-all duration-300 hover:border-lol-gold"
			>
				<!-- Corner gold accent -->
				<div
					class="absolute top-0 right-0 h-8 w-8 bg-linear-to-bl from-[#785A28]/40 to-transparent"
				></div>

				<div class="flex items-start gap-4">
					<div
						class="flex h-12 w-12 shrink-0 items-center justify-center rounded border border-lol-gold-dark bg-lol-bg-panel text-lol-gold transition-colors group-hover:border-lol-gold"
					>
						<item.icon class="h-6 w-6" />
					</div>

					<div class="space-y-1">
						<span
							class="block font-['Beaufort'] text-xs font-bold tracking-widest text-lol-gold-dark uppercase transition-colors group-hover:text-lol-gold"
						>
							{item.label}
						</span>
						<span class="block font-['Spiegel'] text-lg font-bold text-lol-gold-light">
							{item.value}
						</span>
					</div>
				</div>
			</div>
		{/each}
	</div>

	<!-- Extra Flavor Section: Champion / Role Mastery style -->
	<div class="lol-panel-gold space-y-4 rounded p-6">
		<h2
			class="border-b border-lol-gold-dark/50 pb-2 font-['Beaufort'] text-xl font-bold tracking-wider text-lol-gold uppercase"
		>
			TECH STACK MASTERY
		</h2>

		<div class="grid grid-cols-2 gap-4 pt-2 text-center sm:grid-cols-4">
			<div class="rounded border border-lol-gold-dark bg-lol-bg-panel p-3">
				<div class="font-['Beaufort'] text-sm font-bold text-lol-gold sm:text-lg">
					TypeScript / JS
				</div>
				<div class="mt-1 text-xs font-bold text-lol-blue">MASTERY 7</div>
			</div>
			<div class="rounded border border-lol-gold-dark bg-lol-bg-panel p-3">
				<div class="font-['Beaufort'] text-sm font-bold text-lol-gold sm:text-lg">
					Svelte / SvelteKit
				</div>
				<div class="mt-1 text-xs font-bold text-lol-blue">MASTERY 7</div>
			</div>
			<div class="rounded border border-lol-gold-dark bg-lol-bg-panel p-3">
				<div class="font-['Beaufort'] text-sm font-bold text-lol-gold sm:text-lg">TailwindCSS</div>
				<div class="mt-1 text-xs font-bold text-lol-blue">MASTERY 7</div>
			</div>
			<div class="rounded border border-lol-gold-dark bg-lol-bg-panel p-3">
				<div class="font-['Beaufort'] text-sm font-bold text-lol-gold sm:text-lg">Python / C++</div>
				<div class="mt-1 text-xs font-bold text-lol-blue">MASTERY 6</div>
			</div>
		</div>
	</div>
</div>
