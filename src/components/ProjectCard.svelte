<script lang="ts">
	import { BookMarked } from "lucide-svelte";

	interface ProjectCardProps {
		repository: IRepository
	}

	const { repository } : ProjectCardProps = $props()
</script>

<div class="border-1 border-yellow rounded-lg p-4 space-y-2.5">
	<h3 class="text-lg flex space-x-1">
		<BookMarked strokeWidth={1.5}/>
		<a class="underline-decoration font-semibold truncate" href={`https://github.com/${repository.fullName}`}>{repository.fullName}</a>
	</h3>
	<p class="text-yellow-light">{repository.description}</p>
	<span class="text-yellow-light">{repository.language}</span>
</div>