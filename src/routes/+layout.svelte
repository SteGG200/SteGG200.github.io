<script lang="ts">
	import './layout.css';
	import Navbar from '$lib/components/Navbar.svelte';
	import Footer from '$lib/components/Footer.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<title>SteGG200 | League of Legends Portfolio</title>
	<meta
		name="description"
		content="Personal profile website of SteGG200 (Nguyễn Hòa Bình), styled after the League of Legends Client."
	/>
</svelte:head>

<div class="flex min-h-screen flex-col bg-lol-bg-dark text-lol-gold-light">
	<Navbar />
	<main class="mx-auto w-full max-w-7xl flex-1 px-4 pb-8 sm:px-6 lg:px-8">
		{@render children()}
	</main>
	<Footer />
</div>
