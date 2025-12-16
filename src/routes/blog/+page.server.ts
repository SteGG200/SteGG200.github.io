import type { PageServerLoad } from './$types';
import blogs from '$blogs/blogs.json';

export const load: PageServerLoad = async () => {
	const handledBlogs = blogs.map(({ title, preview, tags, createdAt }, index) => {
		return {
			id: index,
			title,
			preview,
			tags,
			createdAt: new Date(createdAt)
		};
	}).sort((blogA, blogB) => {
		if(blogA.createdAt < blogB.createdAt){
			return 1
		}
		return -1
	});

	return {
		blogs: handledBlogs
	};
};
