# Share a complete environment copy

Right-click a local container, VM or built-in Alpine microVM and choose **Create a download link**. Review the files being shared, select a quick public link or a saved custom domain, then turn the link on. Creating the copy stops the environment to keep files and databases consistent. It stays stopped until you start it again.

The copy includes the environment's own filesystem, installed applications, hidden files, configuration and private container-volume data. It includes credentials stored inside that environment. It does not grant access to shared PC folders, external disks, connected environments or the owner's backup history. Connected cloud servers, native branches and custom microVMs do not yet support portable copies.

The link serves one verified, immutable `.yougori` download. Files changed after creating it appear in a new copy when you turn the link off and create another one. The recipient imports the file using **Import backup**, or:

```sh
yougori backup import --path environment.yougori --yes
```

Importing verifies the payload and creates a separate stopped environment with a new ID. Existing environments and their files stay intact. The recipient reviews and grants their own connections and host-folder permissions.

In the CLI's **Manage environment** menu, choose **Environment download link**. For scripts:

```sh
yougori stop ENV
yougori download on ENV --yes
yougori download on ENV --domain copies.example.com --yes
yougori download list
yougori download off ENV_ID
```

`download on` stays in the foreground. Keep that CLI open; Ctrl+C turns the link off. Links also turn off when their owning app or CLI exits, their tunnel stops, or the computer turns off. Starting Yougori again does not restore a link. Create a new one when needed. Custom domains follow the same temporary-link rules and must already be configured in Public access setups. A domain currently serving another node is unavailable for a download link.

**Downloads (all time)** counts completed full-file transfers for the original environment across quick links, custom domains and restarts. It counts repeated downloads again; it does not identify unique people or confirm that a recipient imported the copy. Visiting the landing page, checking headers and interrupted transfers do not increment the total. Downloads currently require a complete transfer rather than range-based resuming.

The app checks for updates automatically every 12 hours and offers **Update** when a newer package exists: after the person confirms, it downloads and checks the release, quits (stopping running environments) and its installer opens the app again. **Preferences → Updates → Check for updates** checks immediately. The CLI offers **Update now** at interactive startup, and `yougori update` does the same from a terminal (`--check` only reports). Updating always requires the user's choice; a signed installation takes only its own publisher's updates, and an unsigned preview is checked against its published SHA-256.
