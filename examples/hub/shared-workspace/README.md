# Shared Workspace

Let one person into one of your sandboxes, with the access you choose.

Shared Workspace gives one person access to one of your existing sandboxes through Yougori's remote gateway. They sign in with their own username and password, and get exactly what you chose: view one folder, edit one folder, or use the whole sandbox. Access ends when the time you set runs out or when you revoke it. Your own sandbox keeps running as before, whatever they do with their access.

```text
yougori template run ./examples/hub/shared-workspace
```

From the Hub, search for "Shared Workspace", or run `yougori run hub/PUBLISHER/shared-workspace@1.0.0` with the publisher shown on its Hub page. Run it once per person you share with.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `recipient` | text | — | Their username: 1 to 64 lowercase letters, digits, dots, dashes or underscores |
| `recipient_name` | text | — | Optional, for your own lists |
| `recipient_password` | secret | — | At least 8 characters; send it separately from the link |
| `permission` | choice | view | view (read one folder), edit (read and change one folder) or control (the whole sandbox) |
| `folder` | text | `/workspace` | An absolute folder inside the sandbox; required for view and edit |
| `expires_hours` | number | 24 | 1 to 8760 hours; empty means until you revoke it |
| `access` | choice | quick | quick or domain |
| `domain` | domain | — | When `access` is domain |

Setup also asks which of your sandboxes to share. That choice belongs to this computer and is never part of the template.

Example answers without secrets are in [`answers/`](answers).

## What each permission gives

| Permission | They can |
| --- | --- |
| view | List and read files in the folder. No terminal. |
| edit | Read and change files in the folder. No terminal. |
| control | Open terminals, run commands, start and stop the sandbox, open graphical apps where the sandbox supports them, and use any tools signed in there. With a folder, also move files in and out of it. |

Files are confined to the folder: paths stay inside it, and links or special files are refused. A full VM can only be shared with control, and its desktop opens for that person.

## What it creates

- An access entry for that person on the chosen sandbox, protected by their password (stored only as a hash).
- The remote gateway, reachable through a quick link or your domain, if it is not already running.

## Outputs

| Output | Value |
| --- | --- |
| Link for the person | Private: shown only to you. The person runs `yougori connect LINK USERNAME` and types the password. |
| Share page | Where you see and manage this share in Yougori |

## Revoking

Remove this setup, or use Revoke in the People view. Their open terminals, file sessions and desktops close at once, and the sandbox keeps running for you. Anything they already changed or started in the sandbox stays; check it if you gave control.

## Known limits

- **The share cannot be changed after setup.** The permission, folder and expiry are fixed once it is made; remove the setup and run the template again to share differently.
- **The link is shown only in Yougori.** It is private, so it is never in the setup's review, its activity or its outputs on screen. Find it in the sandbox's terminal: Ctrl+G, then Manage sharing.
- **One person per setup.** Run the template again for each person.
- **The expiry cannot be changed** after the share is made; revoke it and share again.
- **One gateway serves every share** on this computer: starting it makes every active share reachable.
- **Sessions** last at most 12 hours (or until the share expires) and end after 15 minutes idle; up to 8 sessions per person.
- **Up to 128 people** can hold active shares on this computer.
- **Command-line recipients** get a terminal (control) or file commands (view and edit); graphical apps and desktops need the Yougori app.
- **Quick links** can change after a restart; the link output is refreshed when it does.
- **Choosing folders in setup is planned.** Selected folders is listed as planned and can't be turned on yet, so the share's folder is the one you type, checked when the share is made.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, binding, steps and outputs |
| `yougori.yaml` | The share |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
