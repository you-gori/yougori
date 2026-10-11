// Keeps native runtime ownership after an engine crash. The exec'd runtime
// retains this PID; the watchdog owns only the pipe and its parent's group.
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] != '/') return 64;
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || setpgid(0, 0)) return 70;
    pid_t owner = getpid();
    pid_t watcher = fork();
    if (watcher < 0) return 70;
    if (!watcher) {
        if (setpgid(0, 0)) _exit(70);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        struct pollfd pipe = {STDIN_FILENO, POLLIN | POLLHUP, 0};
        for (;;) {
            // Once reparented, never signal a numeric PID that could be reused.
            if (getppid() != owner) _exit(0);
            int ready = poll(&pipe, 1, 500);
            if (ready < 0 && errno == EINTR) continue;
            if (ready != 0) break;
        }
        if (getppid() == owner) kill(-owner, SIGTERM);
        for (int n = 0; n < 20 && getppid() == owner; ++n) usleep(100000);
        if (getppid() == owner) kill(-owner, SIGKILL);
        _exit(0);
    }
    int null = open("/dev/null", O_RDONLY);
    if (null < 0 || dup2(null, STDIN_FILENO) < 0) return 70;
    if (null != STDIN_FILENO) close(null);
    execv(argv[1], &argv[1]);
    return 71;
}
