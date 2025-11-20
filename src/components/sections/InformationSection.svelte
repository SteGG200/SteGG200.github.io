<script lang="ts">
	import LabelSection from '$components/LabelSection.svelte';

	const generalInformation: { label: string; value: string }[] = [
		{ label: 'Full Name', value: 'Nguyễn Hòa Bình' },
		{ label: 'Current Location', value: 'Hanoi, Vietnam' },
		{ label: 'Current Job', value: 'Student at UET-VNU' },
		{ label: 'Hobbies', value: 'Gaming, Coding, Listening to Music' },
		{ label: 'Favorite Club', value: 'SKT T1' }
	];
</script>

<section id="info" class="flex w-full scroll-mt-30 justify-center">
	<div
		class="w-table max-xl:w-table-xl border-yellow space-y-5 rounded-xl border p-8 max-lg:p-6 max-md:w-11/12 max-md:space-y-3 max-md:p-4"
	>
		<LabelSection>GENERAL INFORMATION</LabelSection>
		<table class="w-full max-sm:table-fixed">
			<tbody class="[&_tr:last-child]:border-0">
				{#each generalInformation as row, index (index)}
					<tr class="border-yellow border-b">
						<td class="p-4 align-middle max-md:p-3 max-sm:p-2">{row.label}</td>
						<td class="text-yellow-light p-4 align-middle max-md:p-3 max-sm:p-2">{row.value}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
</section>
