<script lang="ts">
	import BlogCard from '$components/cards/BlogCard.svelte';

	let { data } = $props();

	$effect(() => {
		window.scrollY;
		window.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
	});
</script>

<svelte:head>
	<title>SteGG's Blogs</title>
</svelte:head>

<main class="min-h-dvh w-full space-y-8 py-12">
	<h1 class="text-center text-4xl font-semibold max-md:text-3xl">SteGG's Blogs</h1>
	<div class="w-blogs-list mx-auto max-xl:w-5/6 max-md:w-11/12 space-y-4">
		{#each data.blogs as blog, index (index)}
			<BlogCard id={index + 1} title={blog.title} tags={blog.tags} createdAt={blog.createdAt} />
		{/each}
	</div>
</main>
