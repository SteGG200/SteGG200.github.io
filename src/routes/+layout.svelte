<script lang="ts">
	import '../app.css';
	let { children } = $props();
</script>

<svelte:head>
	<title>SteGG</title>
</svelte:head>

<div class="w-full min-h-dvh bg-dark">
	{@render children()}
</div>