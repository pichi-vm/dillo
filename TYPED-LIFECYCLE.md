# Typed device lifecycle experiment

Baseline: `25f811fe93ee7e17fc301a53a505acf3c6e435fc`.

Retrofit block and multiport console into a common consuming lifecycle API,
with the same device implementation in local and vhost-user execution. Keep
the current wire protocol, native notifications, batching and buffer reuse.
Do not extract standalone binaries in this milestone.

The core owns the backend and its execution resources. A successful drain is
required before reconfiguration; failed drains retain the stopping owner.
Stopping a queue is separate from stopping a worker: console shares one
worker between its control queues. Enablement is separate from queue life.
Runtime wire validation belongs at the adapter boundary.

Validate partial startup, pending I/O during drain, independent queue restart,
memory replacement, reset and failed cleanup. Exercise both transports and
both execution modes. Use compile-fail examples for illegal lifecycle calls.

Use the existing snuffler paired harness against the baseline on Linux x86
and Arm, macOS Arm and Windows MSVC. Use ordinary vhost-user completion for
both revisions. Run five measured pairs per selected case plus warm-up, then
one bounded noise calibration if needed. Preserve failed observations. Within
measured noise is success; wide uncertainty is inconclusive. Do not spend this
milestone tuning small differences.

At the milestone boundary, report API ergonomics, removed/added state and
allocations, correctness evidence and paired performance, then pause.
