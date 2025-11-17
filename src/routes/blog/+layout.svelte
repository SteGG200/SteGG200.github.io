<script lang="ts">
	import Footer from "$components/footer/Footer.svelte";
	import Header from "$components/header/Header.svelte";

	let { children } = $props()
</script>

<Header/>

{@render children()}

<Footer/>
