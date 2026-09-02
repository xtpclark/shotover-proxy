use shotover::runner::Shotover;

// Opt-in jemalloc allocator (feature "jemalloc"). jemalloc returns freed memory to the OS via a
// background purge thread, so a proxy that assembled a large response train drops back to a near-idle
// footprint instead of retaining ~1 GB for its lifetime under glibc's arena plateau (F13). This does
// NOT reduce the PEAK of a large train (that needs response streaming) — it removes the retention.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Bake the tuning into the binary so operators do not need the `_RJEM_MALLOC_CONF` env var:
// enable the background purge thread and a short decay. tikv-jemallocator namespaces jemalloc's
// symbols with `_rjem_`, so the config symbol jemalloc reads at startup is `_rjem_malloc_conf`.
#[cfg(feature = "jemalloc")]
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static _rjem_malloc_conf: &[u8] =
    b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000\0";

fn main() {
    // Disable anyhow from taking backtraces, which makes for very verbose logs and is possibly a performance issue.
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        // Safety: Safe because this is the first thing in main, we know that we havent launched any other threads which may access set_var.
        // TODO: Avoid usage of unsafe:
        //       Maybe this https://github.com/dtolnay/anyhow/issues/403 ?
        //       Or this https://github.com/rust-lang/rust/issues/93346 ?
        //       Or maybe fork anyhow?
        unsafe { std::env::set_var("RUST_LIB_BACKTRACE", "0") };
    }

    Shotover::new().run_block();
}
