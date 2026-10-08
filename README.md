<div align="center">

# Yougori

### Publish models. Serve inference. Build with AI. Go live.

Serve models through Neo Grid, publish your model files, build in shared AI sandboxes,<br>
and put your apps online from your local project. Use the CLI or App, with access you control.

<br>

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-1f2937?style=for-the-badge)](LICENSE)
[![Platforms](https://img.shields.io/badge/Windows%20·%20Ubuntu%20·%20macOS-1f2937?style=for-the-badge)](#run-from-source)
[![Version](https://img.shields.io/badge/version-1.0.11-1f2937?style=for-the-badge)](package.json)

**[Website](https://yougori.com/)** &nbsp;·&nbsp; **[Discord](https://discord.gg/Eqhf4Hq3AG)** &nbsp;·&nbsp; **[X](https://x.com/withYougori)** &nbsp;·&nbsp; **[Run from source](#run-from-source)**

<br>

<img src="Yoo-app.png" alt="Yougori desktop app" width="49%">
<img src="yougori1.png" alt="Yougori workspace" width="49%">

</div>

<br>

## Four main features

<table>
<tr>
<td width="50%" valign="top">

### Neo Grid — Serve your models

Host supported AI models on your GPU and make them available through Yougori Chat and its API. Offer free inference with `--nowfree`, or use `--now` for supported paid inference with USDC earnings. On free inference, optionally enable `--listen` to record conversations on your provider and understand how people use your model.

</td>
<td width="50%" valign="top">

### AI Model Publishing — Share your models

Publish the models you build with descriptions, versions, licenses and downloadable files. Yougori hosts the model page; your files are served from your publishing environment. Use a local model folder without uploading it to Hugging Face. Choose open downloads or use `--closed-weights` to offer inference while keeping weight downloads closed.

</td>
</tr>
<tr>
<td valign="top">

### Shared AI Sandboxes — Build together

Run AI coding tools in isolated environments, keep their files and share access to the workspace. Launch tools such as Codex and Claude directly in your terminal with `yougori codex` or `yougori claude`. Choose the folders, connections and recipient permissions, then publish the apps you build to a public URL or your own domain.

</td>
<td valign="top">

### Instant App Publishing — Put your project online

Set up your project once, then run `npm run yougori` to start its development command inside a Yougori environment. Sync your project files and choose access for yourself, your local network, a public link or your own domain. Keep the running app's logs and links in your terminal.

</td>
</tr>
</table>

Containers, VMs, connected cloud servers, Neocloud GPUs and Personal Vault MCP support these workflows. Yougori uses USDC for supported paid inference and has no cryptocurrency of its own.

<br>

## Start in your project

Open a terminal in your project folder and run:

```bash
cd my-project
yougori
```

Yougori opens a guided menu and adds shortcuts to supported Node.js projects. Choose the project launch option, or run `yougori launch` directly. Pick your resources, file sync and who can open your app: just you, your local network, a public link or your own domain.

When asked how to run your project, choose **`npm run dev`** if that is your project's development command. Yougori installs dependencies and runs it inside the environment, with logs and links in your terminal.

Next time, start from the same folder:

```bash
npm run yougori
```

Your setup is saved. Yougori syncs once when starting. Setup recommends **Continuously** for project folders below 2.5 GB and **On demand** for folders of 2.5 GB or more; your saved choice remains selected when editing settings. Press `y` when switching where you work: **Sync to container** sends computer changes; **Sync to this computer** brings container changes home when two-way sync is enabled. Your chosen conflict priority applies. Press `t` to open a terminal inside the environment, or `q` / Ctrl+C to stop the project container and keep its files. On-demand sessions do not sync again when quitting.

| What you want to do | Command |
| --- | --- |
| Change resources, access or file sync | `npm run yougori-change` |
| Run on a connected Linux cloud server | `npm run yougori-cloud` |
| Run a supported Python project after registering it with `yougori` | `python yougori` |
| Open the guided menu | `yougori` |

Cloud launch asks which connected server to use. That server needs Docker Engine access for its project containers. Local projects use Yougori's own runtime.

## Run a model. Make it yours.

Choose a supported Hugging Face model and give it a place to run. Start locally:

```bash
yougori model run hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0
```

Yougori guides you through setup and opens a chat when the model is ready. To use Neocloud compute, connect your RunPod account and create or attach a GPU pod through the `yougori` menu, then run:

```bash
yougori model run hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0 --neocloud
```

Need the model in your app? Start it with `--api`:

```bash
yougori model run hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0 --api --port 8000
```

Use the model's environment name or ID in place of `ENV` below. `yougori ps` lists them.

| What you want to do | Command |
| --- | --- |
| Return to a conversation | `yougori model chat ENV` |
| Start a fresh conversation | `yougori model chat ENV --new` |
| Get the API key and connection addresses | `yougori model access ENV` |
| Check the model | `yougori model status ENV` |
| See API usage | `yougori model usage ENV` |
| Stop the model process | `yougori model stop ENV` |

Stopping a model on Neocloud leaves its pod billable. Manage the pod separately in the Neocloud menu.

## Give agents access you approve

Personal Vault MCP keeps credentials and personal information in an encrypted vault on your computer. Your agent requests what it needs; you review the request and approve access.

Run `yougori` and choose **MCP Vault** to open the vault, add an item, review approvals or get your MCP connection settings. Item entry and approvals use the Windows App, which is installed separately from the CLI.

For an MCP client that supports local stdio servers, use:

```json
{
  "mcpServers": {
    "yougori-vault": {
      "command": "yougori",
      "args": ["vault", "mcp"]
    }
  }
}
```

The client must be able to find `yougori` on its PATH. The MCP Vault menu can generate settings with the full executable path. For connection options and approval behavior, see [Personal Vault](docs/personal-vault.txt).

## Keep the rest within reach

Use the guided menu to create containers and VMs, manage Neocloud compute, share folders and set up connections. These commands are useful when you already know what you want:

```bash
yougori status                  # Environments, links and jobs
yougori run -it ubuntu           # Open a shell in an Ubuntu container
yougori terminal ENV             # Open a terminal in an existing environment
yougori logs ENV                 # Read its logs
yougori stop ENV                 # Stop an environment
yougori help                     # Full command reference
```

For projects with several services, describe the environments and connections in [`yougori.yaml`](examples/yougori.yaml). Run `yougori up --dry-run` to preview, `yougori up` to start, and `yougori down` to stop them without deleting their volumes.

More detail: [projects, cloud launch and models](docs/projects-and-models.txt).

<br>

## Run from source

You'll need **Git**, **Node.js 24 LTS** and **Rust stable**.

<details open>
<summary><b>Windows x64</b>: PowerShell</summary>

<br>

```powershell
git clone https://github.com/you-gori/yougori.git
Set-Location yougori
rustup default stable-x86_64-pc-windows-msvc
npm ci
npm run cli:bundle
npm run desktop:dev
```

</details>

<details>
<summary><b>Ubuntu 22.04+ x64</b>: Terminal</summary>

<br>

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libwebkit2gtk-4.1-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev patchelf \
  libssl-dev libxdo-dev qemu-system-x86 qemu-utils ovmf \
  openssh-client ca-certificates

git clone https://github.com/you-gori/yougori.git
cd yougori
npm ci
npm run cli:bundle
npm run desktop:dev
```

</details>

<details>
<summary><b>macOS 14+</b>: Terminal &nbsp;<sub>development preview</sub></summary>

<br>

```bash
git clone https://github.com/you-gori/yougori.git
cd yougori
npm ci
npm run macos:setup
npm run cli:bundle
npm run desktop:dev
```

</details>

<br>

## Documentation

| | |
| --- | --- |
| [Projects, CLI and models](docs/projects-and-models.txt) | Every command, `yougori.yaml` fields and the model runner |
| [Neocloud](docs/neocloud.md) | Renting GPUs, pods, serverless endpoints and volumes |
| [Model publishing](docs/model-publishing.md) | Model pages, downloads, open and closed weights |
| [Tool containers](docs/tool-containers.md) | AI tools running directly in your terminal |
| [Remote sharing](docs/remote-sharing.txt) | Tunnels, domains, recipients and permission levels |
| [Personal Vault](docs/personal-vault.txt) | Encrypted credential broker for agents |
| [Build cache](docs/build-cache.md) | Faster Rust builds during development |
| [Licensing](docs/licensing.txt) | AGPL, commercial licensing and source distribution |

<br>

## License

Yougori's original code is open source under **[AGPL-3.0-only](LICENSE)**, with a **[separate commercial license](COMMERCIAL_LICENSE.txt)** available from Yougori LLC. Commercial use is allowed under the AGPL when its conditions are met. Third-party components keep their own licenses. See [NOTICE](NOTICE) and the [licensing guide](docs/licensing.txt).

<br>

<div align="center">

<sub>Made by Yougori LLC</sub>

</div>
