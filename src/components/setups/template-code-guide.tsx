import { useState } from "react"
import { Button } from "@/components/ui/button"

// Kept alongside the UI so the guide is available offline in every desktop build.
const PYTHON = `from yougori import Setup
from website import create_admin_if_missing, serve

setup = Setup("website", image="python:3.12-alpine",
              files=["app.py", "website.py"], command=["python", "app.py"])
setup.admin()  # Ask for the installer's email and password.
setup.password("api_key", "Model API key", required=False)
gpu = setup.checkbox("gpu_grid", "Enable GPU Grid?")
workers = setup.checkbox("sandbox_grid", "Enable Sandbox Grid?")
setup.grid("gpu", when=gpu)
setup.grid("sandbox", when=workers)
setup.input("visibility", "Who can sign up?", type="choice", default="private",
            choices=[{"value": "private", "label": "Invitation only"},
                     {"value": "public", "label": "Anyone"}])

@setup.on_setup
def initialize(values):
    create_admin_if_missing(values["admin_email"], values["admin_password"])

setup.run(lambda values: serve(values))
`

const JAVASCRIPT = `import { Setup } from 'yougori';
import { createAdminIfMissing, serve } from './website.mjs';

const setup = new Setup({ name: 'website', image: 'node:22-alpine',
  files: ['app.mjs', 'website.mjs'], command: ['node', 'app.mjs'] });
setup.admin(); // Ask for the installer's email and password.
setup.password('api_key', 'Model API key', { required: false });
const gpu = setup.checkbox('gpu_grid', 'Enable GPU Grid?');
const workers = setup.checkbox('sandbox_grid', 'Enable Sandbox Grid?');
setup.grid('gpu', { when: gpu });
setup.grid('sandbox', { when: workers });
setup.input('visibility', 'Who can sign up?', { type: 'choice', default: 'private',
  choices: [{ value: 'private', label: 'Invitation only' },
            { value: 'public', label: 'Anyone' }] });

setup.onSetup(async values => {
  await createAdminIfMissing(values.admin_email, values.admin_password);
});
await setup.run(values => serve(values));
`

export function TemplateCodeGuide() {
  const [language, setLanguage] = useState<"python" | "javascript">("python")
  const [notice, setNotice] = useState("")
  const code = language === "python" ? PYTHON : JAVASCRIPT
  return <details className="my-3 rounded-xl border p-4 text-sm">
    <summary className="cursor-pointer font-medium">Template code &amp; examples</summary>
    <div className="mt-4 space-y-4">
      <p>Build your app inside a Sandbox VM. The included <strong>Yougori setup</strong> package turns questions in your code into an installer for the next person.</p>
      <ol className="list-inside list-decimal space-y-2 text-muted-foreground">
        <li>Open the VM terminal and work in <code>/run/yougori/workspace</code>. Choose an image with Python or Node.js for your app.</li>
        <li>Adapt the example below. Replace the website module with your own application code and include its source files.</li>
        <li>Run <code>{language === "python" ? "python app.py" : "node app.mjs"}</code> inside the VM to write <code>.yougori/setup.json</code>. Without installer answers, the app does not start.</li>
        <li>Select your VMs under My computer → <strong>Create template</strong>. Review the files, questions and connections, then save and publish.</li>
        <li>Others open your template in the Hub and run it. Yougori asks the questions, runs your setup hook, then starts your app inside its VM.</li>
      </ol>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="group" aria-label="Example language" className="flex gap-2">
          <Button size="xs" variant={language === "python" ? "default" : "outline"} aria-pressed={language === "python"} onClick={() => { setLanguage("python"); setNotice("") }}>Python</Button>
          <Button size="xs" variant={language === "javascript" ? "default" : "outline"} aria-pressed={language === "javascript"} onClick={() => { setLanguage("javascript"); setNotice("") }}>JavaScript / TypeScript</Button>
        </div>
        <Button size="xs" variant="outline" onClick={() => {
          if (!navigator.clipboard) { setNotice("Select the code below and copy it."); return }
          void navigator.clipboard.writeText(code).then(() => setNotice("Code copied."), () => setNotice("Select the code below and copy it."))
        }}>Copy example</Button>
      </div>
      <pre className="max-h-80 overflow-auto rounded-lg bg-muted/40 p-4 text-xs leading-relaxed" aria-label="Setup code example"><code>{code}</code></pre>
      {notice ? <p role="status">{notice}</p> : null}
      <p className="text-muted-foreground">Your app creates the admin in its own database and hashes the password. Make the hook safe to run again. Never put real passwords or API keys in source files. For TypeScript, compile your app and include its generated JavaScript files.</p>
      <p className="text-muted-foreground">Use <code>setup.input</code> for text, numbers, choices and multiple choices; <code>setup.checkbox</code> for switches; and <code>setup.password</code> for private answers. Your app reads these answers to decide what each option does.</p>
      <p className="text-muted-foreground"><strong>GPU Grid</strong> connects model workers. <strong>Sandbox Grid</strong> combines CPU and memory workers. A selected grid starts its controller with the installed app; it does not rent hardware or enable GPU passthrough.</p>
      <p className="text-muted-foreground">For your coding agent, the full authoring skill is already inside the VM at <code>.agents/skills/yougori-setup/SKILL.md</code>. Enabled grids also install <code>.agents/skills/yougori-grid/SKILL.md</code>.</p>
    </div>
  </details>
}
