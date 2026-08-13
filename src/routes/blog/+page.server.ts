import { getAllBlogs } from '$lib/utils/blog';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = () => {
	const blogs = getAllBlogs();
	return { blogs };
};
