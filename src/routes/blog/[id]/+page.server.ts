import type { PageServerLoad } from './$types';
import { marked } from 'marked';
import { gfmHeadingId } from 'marked-gfm-heading-id';
import { Status } from '$lib';
import fs from 'fs/promises';
import blogs from '$blogs/blogs.json';

export const load: PageServerLoad = async ({ params }) => {
	const id = parseInt(params.id);
	if (isNaN(id) || id > blogs.length) {
		return {
			status: Status.ERROR,
			error: 'Invalid ID'
		};
	}

	const blog = blogs[id - 1];

	try {
		const markdown = await fs.readFile(`./src/blogs/${blog.file}`, 'utf8');
		marked.use(gfmHeadingId());
		const content = marked(markdown);

		return {
			status: Status.SUCCESS,
			blog: {
				title: blog.title,
				content,
				tags: blog.tags,
				createdAt: new Date(blog.createdAt)
			}
		};
	} catch (err) {
		return {
			status: Status.ERROR,
			error: (err as Error).message
		};
	}
};
