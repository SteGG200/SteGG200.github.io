import type { PageServerLoad } from './$types';
import blogs from '$blogs/blogs.json';

export const load: PageServerLoad = async () => {
	const handledBlogs = blogs.map(({ title, preview, tags, createdAt }) => {
		return {
			title,
			preview,
			tags,
			createdAt: new Date(createdAt)
		};
	});
	return {
		blogs: handledBlogs
	};
};
