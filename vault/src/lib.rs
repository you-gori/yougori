//! The vault is a separate broker. Desktop-only approval and secret entry are
//! checked against the foreground Yougori process; remote MCP cannot use them.
#[cfg(windows)]
mod broker;
#[cfg(windows)]
pub mod client;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub mod platform;
pub mod policy;
pub mod protocol;
#[cfg(windows)]
mod storage;
#[cfg(windows)]
mod task;
pub mod transport;

#[cfg(windows)]
pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [arg, flag, owner, options @ ..]
            if flag == "--owner" && matches!(arg.as_str(), "--install" | "--serve" | "--register") =>
        {
            if &platform::user_sid()? != owner {
                return Err("Personal Vault must be elevated as the same Windows account that opened Yougori. Separate administrator accounts and Windows administrator-protection shadow accounts are not supported in this release. No vault was opened.".into());
            }
            let (desktop, digest) = options_of(options)?;
            match arg.as_str() {
                "--install" => platform::install(desktop, digest),
                "--register" => platform::register(desktop.ok_or("Choose the Yougori Desktop to register")?),
                _ if options.is_empty() => broker::run(),
                _ => Err("Open Personal Vault in Yougori Desktop.".into()),
            }
        }
        _ => Err("Open Personal Vault in Yougori Desktop.".into()),
    }
}
/// Optional `--desktop PATH` and `--sha256 DIGEST` installer arguments.
#[cfg(any(windows, test))]
fn options_of(options: &[String]) -> Result<(Option<&str>, Option<&str>), String> {
    let (mut desktop, mut digest) = (None, None);
    let mut remaining = options.iter();
    while let Some(flag) = remaining.next() {
        let value = remaining.next().ok_or("Missing installer option value")?;
        match flag.as_str() {
            "--desktop" if desktop.is_none() => desktop = Some(value.as_str()),
            "--sha256"
                if digest.is_none()
                    && value.len() == 64
                    && value.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                digest = Some(value.as_str())
            }
            _ => return Err("Unsupported Personal Vault installer option".into()),
        }
    }
    Ok((desktop, digest))
}
#[cfg(test)]
mod tests {
    #[test]
    fn installer_options_are_exact_and_single_valued() {
        let digest = "a".repeat(64);
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        let options = args(&["--desktop", r"C:\Apps\Yougori\yougori.exe", "--sha256", &digest]);
        assert_eq!(
            super::options_of(&options).unwrap(),
            (Some(r"C:\Apps\Yougori\yougori.exe"), Some(digest.as_str()))
        );
        assert_eq!(super::options_of(&[]).unwrap(), (None, None));
        for invalid in [
            args(&["--desktop"]),
            args(&["--sha256", "short"]),
            args(&["--desktop", "a", "--desktop", "b"]),
            args(&["--approve", "yes"]),
        ] {
            assert!(super::options_of(&invalid).is_err(), "{invalid:?}");
        }
    }
}
