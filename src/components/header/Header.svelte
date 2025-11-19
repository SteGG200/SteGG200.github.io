<script lang="ts">
	import { Menu, X } from 'lucide-svelte';
	import NavBar from './NavBar.svelte';
	import { fade } from 'svelte/transition';

	let isOpenMenu = $state(false);
	let dropDownMenu: HTMLElement;
	let dropDownMenuTrigger: HTMLElement;

	const openMenu = () => {
		isOpenMenu = true;
	}

	const closeMenu = () => {
		isOpenMenu = false;
	}

	const handleClick = (event: PointerEvent) => {
		if (!event.target) return;
		const element = event.target as HTMLElement
		if((dropDownMenu.contains(element) && element.tagName !== 'A') || dropDownMenuTrigger.contains(element)) return
		closeMenu()
	}

	$effect(() => {
		document.addEventListener('click', handleClick)

		return () => {
			document.removeEventListener('click', handleClick)
		}
	})
</script>

<header class="border-yellow bg-dark sticky top-0 z-30 w-full border-b">
	<div class="flex max-lg:justify-between w-full py-6">
		<div class="flex w-1/2 justify-center max-2xl:w-1/3">
			<a class="text-2xl font-bold" href="/">SteGG</a>
		</div>
		<div class="flex w-1/2 justify-center max-2xl:w-2/3 max-lg:menu-dropdown" class:top-0={isOpenMenu} class:-top-full={!isOpenMenu} bind:this={dropDownMenu}>
			<div class="lg:hidden flex flex-row-reverse pt-4 pr-4">
				<button onclick={closeMenu}>
					<X size={32}/>
				</button>
			</div>
			<NavBar />
		</div>
		<div class="lg:hidden w-1/6 max-sm:w-fit max-sm:pr-8" bind:this={dropDownMenuTrigger}>
			<button onclick={openMenu}>
				<Menu size={32}/>
			</button>
		</div>
	</div>
</header>

{#if isOpenMenu}
	<div class="lg:hidden overlay" transition:fade={{ duration: 500 }}></div>
{/if}
