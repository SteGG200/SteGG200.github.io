<script lang="ts">
	import PersonalLink from '$components/PersonalLink.svelte';
	import { Facebook, Github, Mail } from 'lucide-svelte';
</script>

<footer class="border-yellow text-yellow w-full border-t-1 py-6">
	<div class="mx-auto w-fit space-y-3 text-center">
		<div class="space-y-3">
			<div class="flex justify-center space-x-5">
				<PersonalLink size={22} href="https://github.com/SteGG200" Icon={Github} />
				<PersonalLink size={22} href="https://www.facebook.com/geor.steven/" Icon={Facebook} />
				<PersonalLink size={22} href="mailto:binhbhgl5@gmail.com" Icon={Mail} />
			</div>
			<div>
				<p>This website is created in 25/12/2024</p>
			</div>
		</div>
		<div class="border-yellow border-t-1 pt-3">
			<p>© Nguyễn Hòa Bình | All Rights Reserved</p>
		</div>
	</div>
</footer>
