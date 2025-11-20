<script lang="ts">
	import { Menu, X } from 'lucide-svelte';
	import NavBar from './NavBar.svelte';
	import { fade } from 'svelte/transition';

	let isOpenMenu = $state(false);
	let dropDownMenu: HTMLElement;
	let dropDownMenuTrigger: HTMLElement;

	const openMenu = () => {
		isOpenMenu = true;
	};

	const closeMenu = () => {
		isOpenMenu = false;
	};

	function handleClick(this: Document, event: MouseEvent) {
		if (!event.target) return;
		const element = event.target as HTMLElement;
		if (
			(dropDownMenu.contains(element) && element.tagName !== 'A') ||
			dropDownMenuTrigger.contains(element)
		)
			return;
		closeMenu();
	}

	$effect(() => {
		document.addEventListener('click', handleClick);

		return () => {
			document.removeEventListener('click', handleClick);
		};
	});
</script>

<header class="border-yellow bg-dark sticky top-0 z-30 w-full border-b">
	<div class="flex w-full py-6 max-lg:justify-between">
		<div class="flex w-1/2 justify-center max-2xl:w-1/3">
			<a class="text-2xl font-bold" href="/">SteGG</a>
		</div>
		<div
			class="max-lg:menu-dropdown flex w-1/2 justify-center max-2xl:w-2/3"
			class:top-0={isOpenMenu}
			class:-top-full={!isOpenMenu}
			bind:this={dropDownMenu}
		>
			<div class="flex flex-row-reverse pt-4 pr-4 lg:hidden">
				<button onclick={closeMenu}>
					<X size={32} />
				</button>
			</div>
			<NavBar />
		</div>
		<div class="w-1/6 max-sm:w-fit max-sm:pr-8 lg:hidden" bind:this={dropDownMenuTrigger}>
			<button onclick={openMenu}>
				<Menu size={32} />
			</button>
		</div>
	</div>
</header>

{#if isOpenMenu}
	<div class="overlay lg:hidden" transition:fade={{ duration: 500 }}></div>
{/if}
