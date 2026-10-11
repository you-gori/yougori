# Offline storage expansion tools

The initramfs carries an unmodified `resize2fs` 1.47.4 executable and only its
required libraries (`libe2p`, `libext2fs`, `libcom_err`, musl loader/libc).
These are isolated in `/usr/local/lib/yougori-storage`; no host filesystem
tools or host disks are exposed to the guest.

Packages are authenticated by Alpine's signed APK index. Build inputs are
recorded in BUILD-PACKAGES.txt; most packages listed there are build-root-only
and are NOT shipped in this private helper directory.

- E2fsprogs source: https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/tag/?h=v1.47.4
- Musl source: https://git.musl-libc.org/cgit/musl/tag/?h=v1.2.6
- Alpine packaging and patches: https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable/main/e2fsprogs
- Musl packaging and patches: https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable/main/musl
- Build/staging recipe: scripts/build-storage-tools.sh
- Initramfs installation recipe: scripts/update-workspace-agent.sh

License texts accompany this file. Before publishing binary releases, provide
the complete corresponding source and Alpine build recipes/patches alongside
the download, as required by the applicable licenses. The storage helper does
not alter the license of Yougori's own independently executed code.
