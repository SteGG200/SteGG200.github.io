<script lang="ts">
	import { BookMarked } from 'lucide-svelte';

	interface ProjectCardProps {
		repository: IRepository;
	}

	const { repository }: ProjectCardProps = $props();
</script>

<div class="border-yellow space-y-2.5 rounded-lg border p-4">
	<h3 class="flex space-x-1 text-lg">
		<BookMarked strokeWidth={1.5} />
		<a
			class="underline-decoration truncate font-semibold"
			href={`https://github.com/${repository.fullName}`}>{repository.fullName}</a
		>
	</h3>
	<p class="text-yellow-light">{repository.description}</p>
	<span class="text-yellow-light">{repository.language}</span>
</div>
