//! Explicit maintainer utility: never starts the engine or a workload.
fn main() -> std::process::ExitCode {
    yougori_lib::release_tools::main()
}
