<script lang="ts">
	import '../app.css';
	let { children } = $props();
</script>

<svelte:head>
	<meta name="description" content="A personal website of Nguyen Hoa Binh (SteGG)" />
	<meta name="keywords" content="personal website, stegg, Nguyen Hoa Binh, stegg200" />
	<meta name="author" content="SteGG" />
</svelte:head>

{@render children()}
