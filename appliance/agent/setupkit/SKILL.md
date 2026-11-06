---
name: yougori-setup
description: Build a reusable application inside a Yougori Sandbox VM using setup declarations in Python, JavaScript or TypeScript.
---

# Yougori setup package

Work in `/run/yougori/workspace`. Python imports `from yougori import Setup`;
JavaScript/TypeScript imports `import { Setup } from 'yougori'`. Both packages are
installed locally by the VM core; no npm/pip download is needed.

Declare a stable lowercase name, an OCI registry image with your runtime, an explicit
list of relative source files, and the argv that starts your app. Do not include data,
tokens, `.env`, keys, databases, `.yougori/answers.json`, or sign-in sessions in files.
Capture never executes code on the host. Run the declaration once inside the VM so
`.yougori/setup.json` exists, then select the VMs in Yougori and create the template.
Only connections between selected VMs are included; outside connections must be
declared separately by the recipient. Do not describe live credentials as defaults.

```python
from yougori import Setup
app = Setup('website', image='python:3.12-alpine', files=['app.py'], command=['python', 'app.py'])
app.admin()
app.checkbox('signup', 'Allow public signup?', default=False)
app.input('provider_key', 'Model API key', type='secret', required=False)
app.input('plan', 'Plan', type='choice', choices=[{'value':'small','label':'Small'}, {'value':'large','label':'Large'}])
app.checkbox('workers', 'Enable Sandbox Grid?', default=False)
app.grid('sandbox', when='workers')

@app.on_setup
def initialize(values):
    # Create the admin in your database if absent; hash the password. Be idempotent.
    pass

app.run(lambda values: start_website(values))
```

The JS equivalents are `new Setup({ name, image, files, command })`, `.onSetup(fn)`
and `await app.run(fn)`. Compile TypeScript in your image and name the built entry
point in `command`. Questions support text, secret, number, choice, multichoice,
yes/no, conditions, hints and required values. API/model endpoints are ordinary
text inputs; credentials are secret inputs. Checkboxes arrive as booleans.

Setup runs inside the installed VM before the application's start callback. Hooks
must tolerate a retry: use transactions and create-if-absent operations. Do not log
answers. A missing answers file declares the template and does not start the app.
Use `gpu` for GPU Grid and `sandbox` for CPU and memory together. No package call
grants host files, enables GPU passthrough, buys cloud resources or publishes ports.
Use the installed `yougori-grid` skill for grid service/contributor operations.
