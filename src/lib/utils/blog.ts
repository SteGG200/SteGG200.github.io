import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { Marked } from 'marked';
import hljs from 'highlight.js/lib/core';
import bash from 'highlight.js/lib/languages/bash';
import cpp from 'highlight.js/lib/languages/cpp';
import python from 'highlight.js/lib/languages/python';
import type { BlogFrontmatter, BlogPost, TocItem } from '$lib/types/blog';

// Register ONLY specified languages per spec requirement
hljs.registerLanguage('bash', bash);
hljs.registerLanguage('sh', bash);
hljs.registerLanguage('cpp', cpp);
hljs.registerLanguage('c++', cpp);
hljs.registerLanguage('c', cpp);
hljs.registerLanguage('python', python);
hljs.registerLanguage('py', python);

const BLOGS_DIR = path.join(process.cwd(), 'src', 'blogs');

export function getAllBlogs(): BlogPost[] {
	if (!fs.existsSync(BLOGS_DIR)) {
		return [];
	}

	const files = fs.readdirSync(BLOGS_DIR).filter((f) => f.endsWith('.md'));

	const blogs: BlogPost[] = files.map((file) => {
		const slug = file.replace(/\.md$/, '');
		const filePath = path.join(BLOGS_DIR, file);
		const fileContent = fs.readFileSync(filePath, 'utf-8');
		const { data, content } = matter(fileContent);
		const blogFrontmatter = data as BlogFrontmatter;

		// Generate clean preview (strip markdown formatting)
		const cleanContent = content
			.replace(/#+\s+/g, '')
			.replace(/```[\s\S]*?```/g, '')
			.replace(/`([^`]+)`/g, '$1')
			.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
			.trim();
		const preview = cleanContent.slice(0, 160) + (cleanContent.length > 160 ? '...' : '');

		return {
			slug,
			title: blogFrontmatter.title || slug,
			tags: Array.isArray(blogFrontmatter.tags) ? blogFrontmatter.tags : [],
			createdAt: blogFrontmatter.createdAt
				? blogFrontmatter.createdAt.toLocaleDateString('en-GB')
				: 'Unknown',
			preview,
		};
	});

	// Sort by date descending
	return blogs.sort((a, b) => {
		if (a.createdAt === 'Unknown') return 1;
		if (b.createdAt === 'Unknown') return -1;
		const [dayA, monthA, yearA] = a.createdAt.split('/').map(Number);
		const [dayB, monthB, yearB] = b.createdAt.split('/').map(Number);
		const dateA = new Date(yearA, monthA - 1, dayA);
		const dateB = new Date(yearB, monthB - 1, dayB);
		return dateB.getTime() - dateA.getTime();
	});
}

function splitHighlightedLines(html: string): string[] {
	const rawLines = html.split('\n');
	const activeSpans: string[] = [];

	return rawLines.map((line) => {
		const lineStart = activeSpans.join('');

		const tagRegex = /<span[^>]*>|<\/span>/g;
		let match: RegExpExecArray | null;
		while ((match = tagRegex.exec(line)) !== null) {
			if (match[0] === '</span>') {
				activeSpans.pop();
			} else {
				activeSpans.push(match[0]);
			}
		}

		const lineEnd = '</span>'.repeat(activeSpans.length);
		return lineStart + line + lineEnd;
	});
}

export function getBlogBySlug(
	slug: string,
): { blog: BlogPost; html: string; toc: TocItem[] } | null {
	const filePath = path.join(BLOGS_DIR, `${slug}.md`);
	if (!fs.existsSync(filePath)) {
		return null;
	}

	const fileContent = fs.readFileSync(filePath, 'utf-8');
	const { data, content } = matter(fileContent);
	const blogFrontmatter = data as BlogFrontmatter;

	const toc: TocItem[] = [];

	// Custom renderer to capture TOC headings and format code blocks
	const marked = new Marked();

	marked.use({
		renderer: {
			heading({ text, depth }) {
				const id = text
					.toLowerCase()
					.replace(/[^\w\s-]/g, '')
					.replace(/\s+/g, '-');
				if (depth === 1 || depth === 2) {
					toc.push({ id, text, level: depth });
				}
				return `<h${depth} id="${id}" class="scroll-mt-24">${text}</h${depth}>`;
			},
			code({ text, lang }) {
				const language = lang && hljs.getLanguage(lang) ? lang : 'plaintext';
				const highlighted = hljs.getLanguage(language)
					? hljs.highlight(text, { language }).value
					: text;

				// Process code into lines with line numbers, preserved tab indentation, and closed spans across lines
				const lines = splitHighlightedLines(highlighted);
				const numberedLines = lines
					.map((line, index) => {
						const formattedLine = (line || ' ').replace(/\t/g, ' '.repeat(3));
						return `<tr class="hover:bg-lol-border/50"><td class="select-none text-right pr-4 text-lol-text-muted/50 w-10 text-xs">${index + 1}</td><td class="pr-4 font-mono whitespace-pre">${formattedLine}</td></tr>`;
					})
					.join('');

				const rawCodeEncoded = encodeURIComponent(text);

				return `
					<div class="code-block-container relative my-6 rounded border border-lol-border-gold bg-lol-bg-dark overflow-hidden group">
						<div class="flex items-center justify-between px-4 py-2 bg-lol-bg-panel border-b border-lol-border-gold text-xs font-['Beaufort'] text-lol-gold">
							<span class="uppercase tracking-widest font-bold">${language}</span>
							<button onclick="navigator.clipboard.writeText(decodeURIComponent('${rawCodeEncoded}')).then(() => { this.innerText = 'COPIED!'; setTimeout(() => this.innerText = 'COPY', 2000); })" class="copy-btn px-2 py-1 rounded bg-lol-bg-dark border border-lol-gold-dark text-lol-gold-light hover:border-lol-gold transition-colors cursor-pointer">
								COPY
							</button>
						</div>
						<div class="overflow-x-auto p-4 text-sm font-mono">
							<table class="w-full border-collapse">
								<tbody>${numberedLines}</tbody>
							</table>
						</div>
					</div>
				`;
			},
		},
	});

	const html = marked.parse(content) as string;

	const blog: BlogPost = {
		slug,
		title: blogFrontmatter.title || slug,
		tags: Array.isArray(blogFrontmatter.tags) ? blogFrontmatter.tags : [],
		createdAt: blogFrontmatter.createdAt
			? blogFrontmatter.createdAt.toLocaleDateString('en-BG')
			: 'Unknown',
		preview: '',
		content,
	};

	return { blog, html, toc };
}
