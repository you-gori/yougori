# GPU-W01: notify waiting requests when loading finishes

The Python runner now uses a condition variable sharing `GPU_LOCK` instead of an
unconditional 250 ms sleep in `gpu_enter()`. Completed loads (including failed
loads) and optimizer configuration/control changes notify waiting requests. A
request rechecks readiness under the same lock before entering inference, so a
notification is never an admission grant by itself.

The state check and wait registration are atomic with respect to notifications.
Multiple requests can wait on the same load; no per-request loader is created.
Already-ready requests proceed without waiting. Active request counts and the
existing generation lock continue to prevent eviction during use.

The 250 ms timeout remains as reconciliation for a missed notification and client
disconnect detection. The existing 30-minute preparation deadline, 20-second
renewable leases, queue bound, private grant authorization and unload policy are
unchanged. The wait releases `GPU_LOCK`; disconnect detection is nonblocking and
does not consume request bytes.

Eight new tests exercise real condition variables, threads and disposable socket
pairs: successful multi-waiter completion, load failure, optimizer disable,
spurious notifications, missed notifications, disconnect cleanup, preparation
deadline and the already-ready path. Notification tests deliberately extend their
fallback wait to 30 seconds, then require completion after a notification, so a
passing test cannot be explained by the normal 250 ms poll.

Verification: 17 optimizer tests passed; the complete offline gate passed 102 tests
across eight suites with no skips on 28 October 2026. These are correctness checks,
not measured production performance. No live engine, model or GPU was started.

This removes the request-side fixed polling delay following observed completion.
It does not complete GPU-W01's host demand path: `optimizer.rs` still has its
one-second scheduler reconciliation loop. Event delivery from runners to that
host scheduler, real workload latency comparisons and other GPU-W01 optimizations
remain separate tasks. Updated runner source reaches users through the normal
rebuild/restart flow; no installed workload was changed in this session.
