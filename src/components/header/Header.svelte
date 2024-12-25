<script lang="ts">
	import NavBar from './NavBar.svelte';
</script>

<header class="border-yellow bg-dark sticky top-0 z-20 w-full border-b-1">
	<div class="text-yellow flex w-full py-6">
		<div class="flex w-1/2 justify-center max-2xl:w-1/3">
			<a class="text-2xl font-bold" href="/">SteGG</a>
		</div>
		<div class="flex w-1/2 justify-center max-2xl:w-2/3 max-lg:hidden">
			<NavBar />
		</div>
	</div>
</header>
