/** Yougori's offline authoring SDK. This module never contacts the host or npm. */
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';

export class Setup {
  constructor({ name, image, files, command }) {
    this.definition = { version: 1, name, image, files, command, questions: [], grids: [] };
    this.hooks = [];
  }
  input(id, question, { type = 'text', ...options } = {}) {
    if (!/^[a-z][a-z0-9_]{0,23}$/.test(id)) throw new Error('Use a lowercase input name of at most 24 characters');
    if (this.definition.questions.some(q => q.id === id)) throw new Error(`Duplicate setup input: ${id}`);
    if (type === 'secret' && 'default' in options) throw new Error('Secret values never belong in a template');
    this.definition.questions.push({ ...options, id, question, type });
    return id;
  }
  email(id = 'admin_email', question = 'Administrator email', options = {}) {
    return this.input(id, question, { pattern: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$', ...options });
  }
  password(id = 'admin_password', question = 'Administrator password', options = {}) {
    return this.input(id, question, { min_length: 12, ...options, type: 'secret' });
  }
  admin() { return { email: this.email(), password: this.password() }; }
  checkbox(id, question, { default: selected = false, ...options } = {}) {
    return this.input(id, question, { ...options, type: 'yesno', default: selected ? 'yes' : 'no' });
  }
  grid(kind, { when } = {}) {
    if (!['gpu', 'sandbox'].includes(kind)) throw new Error('Grid kind is gpu or sandbox (CPU and memory)');
    this.definition.grids.push({ kind, ...(when ? { when } : {}) });
    return kind;
  }
  onSetup(callback) { this.hooks.push(callback); return this; }
  declare() {
    mkdirSync('.yougori', { recursive: true, mode: 0o700 });
    writeFileSync('.yougori/setup.json.tmp', JSON.stringify(this.definition, null, 2), { mode: 0o600 });
    renameSync('.yougori/setup.json.tmp', '.yougori/setup.json');
  }
  async run(start) {
    this.declare();
    const file = process.env.YOUGORI_SETUP_FILE || '.yougori/answers.json';
    if (!existsSync(file)) { console.log('Setup declared. Select this VM and create a template in Yougori.'); return false; }
    const answers = JSON.parse(readFileSync(file, 'utf8'));
    if (!answers || Array.isArray(answers) || typeof answers !== 'object') throw new Error('Invalid setup answers');
    const values = Object.fromEntries(this.definition.questions.map(q => {
      const value = answers[q.id];
      return [q.id, q.type === 'yesno' ? [true, 'yes', 'true'].includes(value)
        : q.type === 'multichoice' ? (Array.isArray(value) ? value : (value || '').split(',').filter(Boolean))
        : q.type === 'number' && value !== undefined && value !== '' ? Number(value) : value];
    }));
    const generation = answers._yougori_generation;
    if (!generation || !existsSync('.yougori/initialized') || readFileSync('.yougori/initialized', 'utf8') !== generation) {
      for (const hook of this.hooks) await hook(values);
      if (generation) writeFileSync('.yougori/initialized', generation, { mode: 0o600 });
    }
    const enabled = this.definition.grids.some(grid => !grid.when || values[grid.when]);
    if (enabled) {
      const grid = spawn('/run/yougori/bin/yougori-probe', ['grid', 'serve'], { stdio: 'inherit' });
      grid.on('error', error => { console.error(`Grid could not start: ${error.message}`); process.exitCode = 1; });
      process.once('exit', () => grid.kill());
    }
    if (answers._yougori_launch) writeFileSync('.yougori/launch-ready', answers._yougori_launch, { mode: 0o600 });
    return start(values);
  }
}
