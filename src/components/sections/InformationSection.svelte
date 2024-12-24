<script lang="ts">
	const generalInformation : {label: string, value: string}[] = [
		{label: "Full Name", value: "Nguyễn Hòa Bình"},
		{label: "Current Location", value: "Hanoi, Vietnam"},
		{label: "Current Job", value: "Student at HSGS"},
		{label: "Hobbies", value: "Gaming, Coding, Listening to Music"},
		{label: "Favorite Club", value: "SKT T1"}
	]
</script>

<section class="w-full text-yellow flex justify-center">
	<div class="w-table max-xl:w-table-xl max-md:w-11/12 border-1 border-yellow rounded-xl p-8 max-lg:p-6 max-md:p-4 space-y-5 max-md:space-y-3">
		<h3 class="text-2xl max-md:text-xl font-semibold">GENERAL INFORMATION</h3>
		<table class="w-full max-sm:table-fixed">
			<tbody class="[&_tr:last-child]:border-0">
				{#each generalInformation as row}
					<tr class="border-b-1 border-yellow">
						<td class="p-4 max-md:p-3 max-sm:p-2 align-middle">{row.label}</td>
            <td class="p-4 max-md:p-3 max-sm:p-2 align-middle text-lightyellow">{row.value}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
</section>