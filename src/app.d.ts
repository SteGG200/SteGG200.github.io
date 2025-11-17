// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
	
	interface IconCustomProps {
		size: number
		strokeWidth: number
		class: string
		[key: string]: any
	}

	interface IExperience {
		year: number;
		description: string;
	}

	interface IProjectInfo {
		owner: string;
		name: string;
	}

	interface IRepository {
		fullName: string;
		description: string;
		language: string;
	}
}

export {};
