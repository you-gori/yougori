export type Values = Record<string, string | number | string[] | boolean | undefined>;
export type Condition = Record<string, string | string[]> | { all: Condition[] } | { any: Condition[] } | { not: Condition };
export interface InputOptions {
  type?: 'text' | 'secret' | 'number' | 'yesno' | 'choice' | 'multichoice';
  required?: boolean;
  hint?: string;
  default?: string | string[] | boolean | number;
  min?: number;
  max?: number;
  max_length?: number;
  pattern?: string;
  min_length?: number;
  when?: Condition;
  choices?: { value: string; label: string; hint?: string }[];
}
export class Setup {
  constructor(options: { name: string; image: string; files: string[]; command: string[] });
  input(id: string, question: string, options?: InputOptions): string;
  email(id?: string, question?: string, options?: InputOptions): string;
  password(id?: string, question?: string, options?: InputOptions): string;
  admin(): { email: string; password: string };
  checkbox(id: string, question: string, options?: InputOptions): string;
  grid(kind: 'gpu' | 'sandbox', options?: { when?: string }): string;
  onSetup(callback: (values: Values) => unknown | Promise<unknown>): this;
  declare(): void;
  run(start: (values: Values) => unknown | Promise<unknown>): Promise<unknown>;
}
