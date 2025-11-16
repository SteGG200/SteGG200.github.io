<script lang="ts">
	import Footer from '$components/footer/Footer.svelte';
	import Header from '$components/header/Header.svelte';

	let position = {
		top: Math.random() * 101,
		left: Math.random() * 101
	};
</script>

<div class="flex min-h-dvh flex-col">
	<Header />
	<main class="text-yellow relative flex-1">
		<p class="pt-6 text-center text-3xl">Sorry! I have not done this page yet.</p>
		<a
			class="text-dark absolute"
			style={`top: ${position.top}%; left: ${position.left}%;`}
			href="/more/love"
		>
			love
		</a>
	</main>
	<Footer />
</div>
