<script lang="ts">
	import NavBar from "./NavBar.svelte";


</script>

<header class="sticky top-0 w-full border-b-1 border-yellow bg-dark z-10">
	<div class="w-full text-yellow flex py-6">
		<div class="w-1/2 max-2xl:w-1/3 flex justify-center">
			<a class="font-bold text-2xl" href="/">SteGG</a>
		</div>
		<div class="max-lg:hidden w-1/2 max-2xl:w-2/3 flex justify-center">
			<NavBar/>
		</div>
	</div>
</header>