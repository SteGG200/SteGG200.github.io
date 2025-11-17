<script lang="ts">
	import avatar from '$lib/assets/more/01/02.jpg';
	import _03 from '$lib/assets/more/01/03.mp4';
	import _04 from '$lib/assets/more/01/04.mp4';
	import _05 from '$lib/assets/more/01/05.mp4';
	import _06 from '$lib/assets/more/01/06.mp4';
	import _07 from '$lib/assets/more/01/07.jpg';
	import _08 from '$lib/assets/more/01/08.jpg';
	import { Home } from 'lucide-svelte';

	const info = [
		{ label: 'Ngày sinh', value: '07/04/2006' },
		{ label: 'Nơi sống', value: 'Chiết Giang, Trung Quốc' },
		{ label: 'Trường cấp 3', value: "Zhejiang Rui'an No.4 Middle School" },
		{ label: 'Đại học', value: 'Học viện Hý kịch Trung ương' },
		{ label: 'Chiều cao', value: '1m62-64' }
	];
</script>

<main class="text-yellow mx-auto w-4xl py-20">
	<div class="bg-dark-sm border-yellow space-y-4 rounded-xl border p-6">
		<a href="/more/love">
			<Home />
		</a>
		<img
			class="border-yellow aspect-square w-[220px] rounded-full border"
			src={avatar}
			alt="Li Min Xuan"
		/>
		<h2 class="text-2xl font-semibold">Lý Mẫn Hiên <span class="font-medium">(李闽轩)</span></h2>
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
			Chị xinh và cute, đơn giản thế thôi 🥰 🥰. Mình biết việc chị làm nhưng mà mình lỡ mê vẻ đẹp này
			mất rồi 🥲 nên là mình vẫn có thể chấp nhận.
		</p>
		<p class="text-lg font-semibold">Dưới đây là một vài bức ảnh hoặc video mà mình có được:</p>
		<div class="mx-auto max-w-[400px] space-y-2">
			<video class="h-auto w-full" controls>
				<track kind="captions" />
				<source src={_03} type="video/mp4" />
			</video>
			<video class="h-auto w-full" controls>
				<track kind="captions" />
				<source src={_04} type="video/mp4" />
			</video>
			<video class="h-auto w-full" controls>
				<track kind="captions" />
				<source src={_05} type="video/mp4" />
			</video>
			<video class="h-auto w-full" controls>
				<track kind="captions" />
				<source src={_06} type="video/mp4" />
			</video>
			<img src={_07} alt="Li Min Xuan" />
			<img src={_08} alt="Li Min Xuan" />
		</div>
		<p>Còn nhiều ảnh với video nữa nhưng mà không up lên được 🥲</p>
	</div>
</main>
