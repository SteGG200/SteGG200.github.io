import { error } from '@sveltejs/kit';
import { getBlogBySlug } from '$lib/utils/blog';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = ({ params }) => {
	const result = getBlogBySlug(params.name);
	if (!result) {
		error(404, 'Blog post not found');
	}
	return result;
};
