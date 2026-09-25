# Historical simulator data — not secure-MPC performance

`simulator-only-benchmark.csv` was produced by the removed single-process
simulator. That simulator kept both shares in one process, reconstructed
private operands for comparisons and midpoints, and exchanged no messages.
Its `modeled_network_ms` column is a latency/bandwidth *model* applied to a
guessed byte count, not a measurement.

These numbers say nothing about the performance or security of the
two-party implementation. See `docs/BENCHMARKS.md` for real two-process
measurements.
