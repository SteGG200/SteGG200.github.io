export interface Project {
	id?: string | number;
	repoName: string; // e.g. "SteGG200/storage"
	description: string;
	techStack: string; // e.g. "Go + Nextjs"
	url?: string;
	stars?: number;
	forks?: number;
}
