<script lang="ts">
	interface Props {
		name?: string;
		level?: number;
	}

	// Age calculated dynamically from birth year 2007
	// const currentYear = new Date().getFullYear();
	// const age = currentYear - 2007

	let { name = 'Nguyễn Hòa Bình' }: Props = $props();
</script>

<div class="relative flex w-full max-w-65 flex-col items-center select-none">
	<div
		class="relative aspect-263/700 h-175 animate-down bg-[url(/images/banner.webp)] bg-cover max-lg:h-162.5"
	>
		<!-- Avatar -->
		<div class="flex h-[55%] w-full items-end justify-center">
			<div class="relative aspect-square w-[83%]">
				<img
					class="absolute absolute-avatar-center h-[56%] w-[56%] rounded-full"
					src="/images/avatar.jpg"
					alt="Avatar"
				/>
				<div
					class="absolute top-0 left-0 h-full w-full bg-[url(/images/frame.webp)] bg-cover"
				></div>
			</div>
		</div>
		<!-- Name -->
		<div class="w-full pt-6">
			<p class="text-center font-beaufort text-xl font-bold text-lol-gold-light">{name}</p>
		</div>
	</div>
</div>
