export interface BlogFrontmatter {
	title: string;
	tags: string[];
	createdAt: string;
}

export interface BlogPost {
	slug: string;
	title: string;
	tags: string[];
	createdAt: string;
	preview: string;
	content?: string;
}

export interface TocItem {
	id: string;
	text: string;
	level: number;
}
