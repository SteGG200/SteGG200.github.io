<script lang="ts">
	import avatar from '$lib/assets/more/02/01.jpg'

	const info = [
		{label: 'Ngày sinh', value: '01/02/2007'},
		{label: 'Nơi sống', value: 'Bắc Giang, Việt Nam'},
		{label: 'Trường cấp 3', value: "Trường THPT Yên Dũng số 2"},
		{label: 'Chiều cao', value: '1m60'}
	]
</script>

<main class="w-4xl mx-auto py-20 text-yellow">
	<div class="bg-dark-sm border-1 border-yellow rounded-xl p-6 space-y-4">
		<img class="w-[220px] aspect-square border-1 border-yellow rounded-full" src={avatar} alt="PMH">
		<h2 class="text-2xl font-semibold">Phạm Mai Hương</h2>
		<table>
			<tbody>
				{#each info as row}
					<tr>
						<td class="p-3 align-middle font-semibold">{row.label}:</td>
						<td class="p-3 align-middle text-yellow-light">{row.value}</td>
					</tr>
				{/each}
			</tbody>
		</table>
		<p class="text-yellow-light"><span class="text-yellow font-semibold">Mô tả: </span>
			Mình crush bạn này từ năm lớp 4, học cùng lớp trong năm cấp 2. Đến cấp 3 thì mình lên Hà Nội học nên cũng không bao giờ gặp bạn nữa.
		</p>
		<!-- <p class="font-semibold text-lg">Dưới đây là một vài bức ảnh hoặc video mà mình có được:</p>
		<div class="max-w-[400px] mx-auto space-y-2">
			
		</div> -->
	</div>
</main>