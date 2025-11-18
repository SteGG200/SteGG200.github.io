import type { PageServerLoad } from "./$types"
import { marked } from 'marked'
import { Status } from "$lib"
import fs from 'fs/promises'
import blogs from '$blogs/blog.json'

export const load: PageServerLoad = async ({ params }) => {
	const id = parseInt(params.id)
	if (isNaN(id) || id > blogs.length){
		return {
			status: Status.ERROR,
			error: "Invalid ID"
		}
	}

	const blog = blogs[id - 1]
	
	try {
		const markdown = await fs.readFile(`./src/blogs/${blog.file}`, "utf8")
		const content = marked.parse(markdown)

		return {
			status: Status.SUCCESS,
			blog: {
				title: blog.title,
				content,
				tags: blog.tags,
				createdAt: new Date(blog.createdAt)
			}
		}
	}catch (err) {
		return {
			status: Status.ERROR,
			error: (err as Error).message
		}
	}
}
