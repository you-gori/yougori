#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

struct mount_attr {
  uint64_t attr_set;
  uint64_t attr_clr;
  uint64_t propagation;
  uint64_t userns_fd;
};

static void fail(const char *operation) {
  fprintf(stderr, "%s: %s\n", operation, strerror(errno));
  exit(1);
}

static bool starts_with(const char *value, const char *prefix) {
  return strncmp(value, prefix, strlen(prefix)) == 0;
}

// Pin each directory inode. A workload can rename its directories, but cannot
// turn an intermediate symlink into a lookup in the appliance's root.
static int open_relative_directory(int root, const char *relative, bool create) {
  if (!*relative || relative[0] == '/' || strlen(relative) >= 4096) {
    errno = EINVAL;
    return -1;
  }
  char *copy = strdup(relative);
  if (!copy) return -1;
  int directory = fcntl(root, F_DUPFD_CLOEXEC, 3);
  if (directory < 0) { free(copy); return -1; }
  char *part = copy;
  for (;;) {
    char *separator = strchr(part, '/');
    if (separator) *separator = '\0';
    if (!*part || strcmp(part, ".") == 0 || strcmp(part, "..") == 0) {
      errno = EINVAL;
      break;
    }
    int next = openat(directory, part, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0 && errno == ENOENT && create) {
      if (mkdirat(directory, part, 0755) != 0 && errno != EEXIST) break;
      next = openat(directory, part, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (next < 0) break;
    close(directory);
    directory = next;
    if (!separator) { free(copy); return directory; }
    part = separator + 1;
  }
  int saved_errno = errno;
  close(directory);
  free(copy);
  errno = saved_errno;
  return -1;
}

static int make_shared_alias(int root) {
  int directory = open_relative_directory(root, "yougori", true);
  if (directory < 0) return -1;
  const char *target = "/opendock/shared";
  int result = symlinkat(target, directory, "shared");
  if (result < 0 && errno == EEXIST) {
    char existing[128];
    ssize_t length = readlinkat(directory, "shared", existing, sizeof(existing));
    result = length == (ssize_t)strlen(target) &&
             memcmp(existing, target, strlen(target)) == 0 ? 0 : -1;
    if (result < 0) errno = EEXIST;
  }
  int saved_errno = errno;
  close(directory);
  errno = saved_errno;
  return result;
}

int main(int argc, char **argv) {
  bool unmount_only = argc == 4 && strcmp(argv[2], "--unmount") == 0;
  bool shared_alias = argc == 3 && strcmp(argv[2], "--shared-alias") == 0;
  if (argc != 5 && !unmount_only && !shared_alias) {
    fprintf(stderr, "usage: opendock-mount-helper <pid> <source> <destination> <read-only>\n");
    return 2;
  }
  char *end = NULL;
  errno = 0;
  long pid = strtol(argv[1], &end, 10);
  if (errno || pid <= 1 || pid > INT_MAX || end == argv[1] || *end != '\0') {
    fprintf(stderr, "invalid target process identifier\n");
    return 2;
  }
  const char *source = argv[2];
  const char *destination = shared_alias ? "/yougori/shared" : argv[3];
  bool read_only = !unmount_only && !shared_alias && strcmp(argv[4], "true") == 0;
  if (!shared_alias && ((!unmount_only && !starts_with(source, "/var/lib/opendock/shares/") &&
       !starts_with(source, "/var/lib/opendock/secrets/")) ||
      (!starts_with(destination, "/opendock/shared/") &&
       !starts_with(destination, "/opendock/secrets/")) ||
      strstr(source, "..") != NULL || strstr(destination, "..") != NULL)) {
    fprintf(stderr, "mount path is outside the Yougori share roots\n");
    return 2;
  }

  if (!unmount_only && !shared_alias && strcmp(argv[4], "true") != 0 && strcmp(argv[4], "false") != 0) {
    fprintf(stderr, "invalid read-only flag\n");
    return 2;
  }
  char process_path[128];
  if (snprintf(process_path, sizeof(process_path), "/proc/%ld", pid) >= (int)sizeof(process_path)) {
    fprintf(stderr, "mount target path is too long\n");
    return 2;
  }
  int process = open(process_path, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (process < 0 && unmount_only && errno == ENOENT) return 0;
  if (process < 0) fail("open environment process");
  // These two known procfs links belong to the pinned process, not its image.
  int root = openat(process, "root", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (root < 0 && unmount_only && errno == ENOENT) { close(process); return 0; }
  if (root < 0) fail("open environment root");
  if (shared_alias) {
    if (make_shared_alias(root) != 0) fail("create shared folder alias");
    close(root);
    close(process);
    return 0;
  }
  int namespace_fd = openat(process, "ns/mnt", O_RDONLY | O_CLOEXEC);
  if (namespace_fd < 0) fail("open environment mount namespace");
  int target_fd = open_relative_directory(root, destination + 1, !unmount_only);
  close(root);
  close(process);
  if (unmount_only) {
    // Do not require an umount binary in the container, and do not chroot into
    // an untrusted image. Resolve its mount before entering its namespace.
    if (target_fd < 0 && errno == ENOENT) { close(namespace_fd); return 0; }
    if (target_fd < 0) fail("open unmount target");
    if (setns(namespace_fd, CLONE_NEWNS) != 0) fail("enter environment mount namespace");
    if (fchdir(target_fd) != 0) fail("enter unmount target");
    if (umount2(".", MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) fail("detach shared folder");
    close(target_fd);
    close(namespace_fd);
    return 0;
  }
  if (target_fd < 0) fail("open mount target");
  int appliance_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (appliance_root < 0) fail("open appliance root");
  int source_fd = open_relative_directory(appliance_root, source + 1, false);
  close(appliance_root);
  if (source_fd < 0) fail("open selected shared folder");
  int tree = syscall(SYS_open_tree, source_fd, "",
                     AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
  close(source_fd);
  if (tree < 0) {
    fail("clone source mount");
  }
  if (read_only) {
    struct mount_attr attributes = {.attr_set = MOUNT_ATTR_RDONLY};
    if (syscall(SYS_mount_setattr, tree, "", AT_EMPTY_PATH, &attributes,
                sizeof(attributes)) != 0) {
      fail("make cloned mount read-only");
    }
  }
  if (setns(namespace_fd, CLONE_NEWNS) != 0) {
    fail("enter environment mount namespace");
  }
  if (syscall(SYS_move_mount, tree, "", target_fd, "",
              MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) != 0) {
    fail("attach cloned mount");
  }
  close(namespace_fd);
  close(target_fd);
  close(tree);
  return 0;
}
