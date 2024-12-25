<script lang="ts">
	import avatar from '$lib/assets/more/02/01.jpg';
	import { Home } from 'lucide-svelte';

	const info = [
		{ label: 'Ngày sinh', value: '01/02/2007' },
		{ label: 'Nơi sống', value: 'Bắc Giang, Việt Nam' },
		{ label: 'Trường cấp 3', value: 'Trường THPT Yên Dũng số 2' },
		{ label: 'Chiều cao', value: '1m60' }
	];
</script>

<main class="text-yellow mx-auto w-4xl py-20">
	<div class="bg-dark-sm border-yellow space-y-4 rounded-xl border-1 p-6">
		<a href="/more/love">
			<Home />
		</a>
		<img
			class="border-yellow aspect-square w-[220px] rounded-full border-1"
			src={avatar}
			alt="PMH"
		/>
		<h2 class="text-2xl font-semibold">Phạm Mai Hương</h2>
		<table>
			<tbody>
				{#each info as row}
					<tr>
						<td class="p-3 align-middle font-semibold">{row.label}:</td>
						<td class="text-yellow-light p-3 align-middle">{row.value}</td>
					</tr>
				{/each}
			</tbody>
		</table>
		<p class="text-yellow-light">
			<span class="text-yellow font-semibold">Mô tả: </span>
			Mình crush bạn này từ năm lớp 4, học cùng lớp trong năm cấp 2. Đến cấp 3 thì mình lên Hà Nội học
			nên cũng không bao giờ gặp bạn nữa.
		</p>
		<!-- <p class="font-semibold text-lg">Dưới đây là một vài bức ảnh hoặc video mà mình có được:</p>
		<div class="max-w-[400px] mx-auto space-y-2">
			
		</div> -->
	</div>
</main>
