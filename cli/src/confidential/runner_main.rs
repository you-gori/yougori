fn main() {
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            eprintln!("Cannot disable runner core dumps");
            std::process::exit(1)
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if runtime
        .block_on(yougori_cli::confidential::runner::serve())
        .is_err()
    {
        eprintln!("Confidential runner initialization or execution failed; no hardware privacy is claimed.");
        std::process::exit(1);
    }
}
