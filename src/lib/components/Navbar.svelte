<script lang="ts">
	import { page } from '$app/state';
	import { Menu, X } from '@lucide/svelte';

	let menuOpen = $state(false);

	const navItems = [
		{ name: 'OVERVIEW', href: '/' },
		{ name: 'INFORMATION', href: '/info' },
		{ name: 'EXPERIENCES', href: '/exp' },
		{ name: 'PROJECTS', href: '/proj' },
		{ name: 'BLOGS', href: '/blog' },
	];

	function isActive(href: string): boolean {
		if (href === '/') {
			return page.url.pathname === '/';
		}
		return page.url.pathname.startsWith(href);
	}

	function closeMenu() {
		menuOpen = false;
	}
</script>

<header
	class="sticky top-0 z-50 border-b border-lol-border-gold bg-lol-bg-dark/95 backdrop-blur-md"
>
	<div class="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
		<!-- Brand Logo -->
		<a href="/" onclick={closeMenu} class="group flex items-center gap-2">
			<span
				class="font-['Beaufort'] text-2xl font-bold tracking-wider text-lol-gold drop-shadow-[0_0_8px_rgba(200,170,110,0.3)] transition-colors group-hover:text-lol-gold-light"
			>
				SteGG200
			</span>
		</a>

		<!-- Desktop Navigation Links (≥ lg / 64rem) -->
		<nav class="hidden items-center gap-6 lg:flex">
			{#each navItems as item (item.href)}
				<a
					href={item.href}
					class="relative px-2 py-4 font-['Beaufort'] text-base font-bold tracking-widest uppercase transition-all duration-200
						{isActive(item.href)
						? 'text-lol-gold drop-shadow-[0_0_6px_rgba(200,170,110,0.5)]'
						: 'text-lol-text-muted hover:text-lol-gold-light'}"
				>
					{item.name}
					{#if isActive(item.href)}
						<span
							class="absolute right-0 bottom-0 left-0 h-0.5 bg-lol-gold shadow-[0_0_8px_#C8AA6E]"
						></span>
					{/if}
				</a>
			{/each}

			<a
				href="https://www.facebook.com/geor.steven/"
				target="_blank"
				rel="noopener noreferrer"
				class="px-2 py-4 font-['Beaufort'] text-base font-bold tracking-widest text-lol-text-muted uppercase transition-colors hover:text-lol-gold-light"
			>
				CONTACT
			</a>
		</nav>

		<!-- Mobile Hamburger Toggle Button (< lg / 64rem) -->
		<button
			onclick={() => (menuOpen = !menuOpen)}
			aria-label="Toggle Navigation Menu"
			class="rounded border border-lol-gold-dark p-2 text-lol-gold transition-colors hover:border-lol-gold hover:text-lol-gold-light lg:hidden"
		>
			{#if menuOpen}
				<X class="h-6 w-6" />
			{:else}
				<Menu class="h-6 w-6" />
			{/if}
		</button>
	</div>

	<!-- Mobile Dropdown Menu (< lg / 64rem) -->
	{#if menuOpen}
		<div
			class="border-t border-lol-border-gold bg-lol-bg-panel/95 px-4 py-4 backdrop-blur-md lg:hidden"
		>
			<nav class="flex flex-col space-y-2">
				{#each navItems as item (item.href)}
					<a
						href={item.href}
						onclick={closeMenu}
						class="rounded px-4 py-3 font-['Beaufort'] text-sm font-bold tracking-widest uppercase transition-colors
							{isActive(item.href)
							? 'border-l-2 border-lol-gold bg-lol-bg-panel-light text-lol-gold'
							: 'text-lol-text-muted hover:bg-lol-bg-panel-light/50 hover:text-lol-gold-light'}"
					>
						{item.name}
					</a>
				{/each}
				<a
					href="https://www.facebook.com/geor.steven/"
					target="_blank"
					rel="noopener noreferrer"
					onclick={closeMenu}
					class="rounded px-4 py-3 font-['Beaufort'] text-sm font-bold tracking-widest text-lol-text-muted uppercase transition-colors hover:bg-lol-bg-panel-light/50 hover:text-lol-gold-light"
				>
					CONTACT
				</a>
			</nav>
		</div>
	{/if}

	<!-- LOL Decorative Gold Line -->
	<div class="h-px bg-linear-to-r from-transparent via-[#C8AA6E]/40 to-transparent"></div>
</header>
