//! G08 item 1: the bundle manifest (helper id, versioned ABI with its compatibility rules,
//! supported runners, per-file content digests), strict and canonical, and the bundle
//! framing that checks every file against it.

use super::*;

fn manifest_bytes() -> Vec<u8> {
    bundle_at(version(1, 2, 0), HelperAbi::new(1, 0))
        .manifest()
        .to_bytes()
        .unwrap()
}

fn manifest_text() -> String {
    String::from_utf8(manifest_bytes()).unwrap()
}

fn read(text: &str) -> Result<HelperManifest, ManifestError> {
    HelperManifest::from_bytes(text.as_bytes())
}

fn file(name: &str, bytes: &[u8]) -> HelperFile {
    HelperFile::describe(path(name), bytes)
}

fn manifest_with(
    runners: Vec<BackendRelease>,
    entry: &str,
    files: Vec<HelperFile>,
) -> Result<HelperManifest, ManifestError> {
    HelperManifest::new(
        helper_id(),
        version(1, 0, 0),
        HelperAbi::new(1, 0),
        runners,
        path(entry),
        files,
    )
}

#[test]
fn a_bundle_round_trips_through_its_one_encoding() {
    let built = bundle_at(version(1, 2, 0), HelperAbi::new(1, 0));
    let bytes = built.encode().unwrap();
    assert_eq!(&bytes[..8], b"YGHELPER");
    let decoded = HelperBundle::decode(&bytes).unwrap();
    assert_eq!(decoded, built);
    assert_eq!(decoded.encode().unwrap(), bytes);

    let manifest = decoded.manifest();
    assert_eq!(manifest.helper(), &helper_id());
    assert_eq!(manifest.version(), version(1, 2, 0));
    assert_eq!(manifest.abi(), HelperAbi::new(1, 0));
    // Canonical order: files by path, runners by backend then version.
    let paths: Vec<&str> = manifest
        .files()
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths, ["gpu_optimizer.py", "lib/util.py"]);
    assert_eq!(manifest.runners(), [vllm(), llama()]);
    assert!(manifest.supports(&llama()));
    assert!(!manifest.supports(&vllm_next()));
    assert_eq!(
        manifest.backends(),
        BTreeSet::from([Backend::Vllm, Backend::LlamaCpp])
    );
    // Every file is pinned by its content key and length.
    for (entry, bytes) in decoded.files() {
        assert_eq!(entry.content_key, ContentKey::of(bytes));
        assert_eq!(entry.length_bytes, u64::try_from(bytes.len()).unwrap());
    }
    assert_eq!(decoded.entry(), Some(ENTRY_SOURCE));
    assert_eq!(decoded.file(&path("lib/util.py")), Some(UTIL_SOURCE));
    assert_eq!(decoded.file(&path("missing.py")), None);
}

#[test]
fn the_manifest_is_read_strictly() {
    let text = manifest_text();
    assert!(read(&text).is_ok());
    assert!(text.starts_with("{\"format\":1,\"helper\":\"gpu-optimizer\",\"version\":\"1.2.0\""));

    let unknown = text.replacen("{\"format\":1,", "{\"format\":1,\"extra\":true,", 1);
    assert!(matches!(
        read(&unknown),
        Err(ManifestError::Malformed { .. })
    ));
    let missing = text.replacen(",\"entry\":\"gpu_optimizer.py\"", "", 1);
    assert!(matches!(
        read(&missing),
        Err(ManifestError::Malformed { .. })
    ));
    let newer = text.replacen("{\"format\":1,", "{\"format\":2,", 1);
    assert_eq!(
        read(&newer),
        Err(ManifestError::UnsupportedFormat { found: 2 })
    );
    let newer_shape = "{\"format\":7,\"anything\":[]}";
    assert_eq!(
        read(newer_shape),
        Err(ManifestError::UnsupportedFormat { found: 7 })
    );
    for (from, to) in [
        ("\"gpu-optimizer\"", "\"gpu optimizer\""),
        ("\"1.2.0\"", "\"1.2\""),
        ("\"1.2.0\"", "\"01.2.0\""),
        (
            "{\"major\":1,\"minor\":0}",
            "{\"major\":1,\"minor\":0,\"patch\":0}",
        ),
        ("{\"major\":1,\"minor\":0}", "{\"major\":-1,\"minor\":0}"),
        ("\"backend\":\"vllm\"", "\"backend\":\"sglang\""),
        (
            "\"gpu_optimizer.py\",\"files\"",
            "\"../gpu_optimizer.py\",\"files\"",
        ),
        ("\"lib/util.py\"", "\"/lib/util.py\""),
        ("\"lib/util.py\"", "\"lib/.util.py\""),
    ] {
        assert!(text.contains(from), "{from}");
        let changed = text.replacen(from, to, 1);
        assert!(
            matches!(read(&changed), Err(ManifestError::Malformed { .. })),
            "{to}: {:?}",
            read(&changed)
        );
    }
    let oversized = format!("{text}{}", " ".repeat(MAX_MANIFEST_BYTES));
    assert_eq!(
        read(&oversized),
        Err(ManifestError::TooLarge {
            max_bytes: MAX_MANIFEST_BYTES
        })
    );
}

#[test]
fn the_manifest_has_exactly_one_encoding() {
    let manifest = bundle_at(version(1, 2, 0), HelperAbi::new(1, 0))
        .manifest()
        .clone();
    let text = manifest_text();
    // Whitespace, another file order, another runner order and upper-case digests are
    // the same content in another encoding.
    let pretty = serde_json::to_string_pretty(&manifest).unwrap();
    assert_eq!(read(&pretty), Err(ManifestError::NotCanonical));
    let [first, second] = manifest.files() else {
        panic!("two files expected");
    };
    let first = serde_json::to_string(first).unwrap();
    let second = serde_json::to_string(second).unwrap();
    let swapped = text.replacen(
        &format!("[{first},{second}]"),
        &format!("[{second},{first}]"),
        1,
    );
    assert_ne!(swapped, text);
    assert_eq!(read(&swapped), Err(ManifestError::NotCanonical));
    let vllm_text = "{\"backend\":\"vllm\",\"version\":\"0.29.0\"}";
    let llama_text = "{\"backend\":\"llama_cpp\",\"version\":\"b11425\"}";
    let reordered = text.replacen(
        &format!("[{vllm_text},{llama_text}]"),
        &format!("[{llama_text},{vllm_text}]"),
        1,
    );
    assert_ne!(reordered, text);
    assert_eq!(read(&reordered), Err(ManifestError::NotCanonical));
    let key = manifest.files()[0].content_key.to_string();
    let upper = text.replacen(&key, &key.to_uppercase(), 1);
    assert_eq!(read(&upper), Err(ManifestError::NotCanonical));
    assert_eq!(read(&text).unwrap(), manifest);
}

#[test]
fn the_manifest_bounds_its_files_and_runners() {
    let entry = file("gpu_optimizer.py", ENTRY_SOURCE);
    assert_eq!(
        manifest_with(vec![vllm()], "gpu_optimizer.py", vec![]),
        Err(ManifestError::NoFiles)
    );
    let many: Vec<HelperFile> = (0..=MAX_HELPER_FILES)
        .map(|index| file(&format!("f{index}.py"), b"x"))
        .collect();
    assert_eq!(
        manifest_with(vec![vllm()], "f0.py", many),
        Err(ManifestError::TooManyFiles {
            max: MAX_HELPER_FILES
        })
    );
    // Paths are compared without case, so no file system merges two files.
    assert_eq!(
        manifest_with(
            vec![vllm()],
            "gpu_optimizer.py",
            vec![entry.clone(), file("GPU_Optimizer.py", b"other")]
        ),
        Err(ManifestError::DuplicateFile {
            path: path("GPU_Optimizer.py")
        })
    );
    let mut large = entry.clone();
    large.length_bytes = MAX_HELPER_FILE_BYTES + 1;
    assert_eq!(
        manifest_with(vec![vllm()], "gpu_optimizer.py", vec![large]),
        Err(ManifestError::FileTooLarge {
            path: path("gpu_optimizer.py"),
            max_bytes: MAX_HELPER_FILE_BYTES
        })
    );
    let full: Vec<HelperFile> = (0..5)
        .map(|index| HelperFile {
            length_bytes: MAX_HELPER_FILE_BYTES,
            ..file(&format!("f{index}.py"), b"x")
        })
        .collect();
    assert_eq!(
        manifest_with(vec![vllm()], "f0.py", full),
        Err(ManifestError::FilesTooLarge {
            max_bytes: MAX_HELPER_FILES_BYTES
        })
    );
    assert_eq!(
        manifest_with(vec![vllm()], "main.py", vec![entry.clone()]),
        Err(ManifestError::EntryNotListed {
            entry: path("main.py")
        })
    );
    assert_eq!(
        manifest_with(vec![], "gpu_optimizer.py", vec![entry.clone()]),
        Err(ManifestError::NoRunners)
    );
    assert_eq!(
        manifest_with(
            vec![vllm(), llama(), vllm()],
            "gpu_optimizer.py",
            vec![entry.clone()]
        ),
        Err(ManifestError::DuplicateRunner { runner: vllm() })
    );
    let runners: Vec<BackendRelease> = (0..=MAX_HELPER_RUNNERS)
        .map(|index| BackendRelease::new(Backend::Vllm, &format!("0.{index}.0")).unwrap())
        .collect();
    assert_eq!(
        manifest_with(runners, "gpu_optimizer.py", vec![entry]),
        Err(ManifestError::TooManyRunners {
            max: MAX_HELPER_RUNNERS
        })
    );
}

#[test]
fn ids_versions_and_paths_follow_their_rules() {
    assert!(HelperId::new("gpu-optimizer").is_ok());
    assert!(HelperId::new("gpu optimizer").is_err());
    assert!(HelperId::new("").is_err());

    assert_eq!(HelperVersion::parse("1.2.3"), Ok(version(1, 2, 3)));
    assert_eq!(HelperVersion::parse("0.0.0"), Ok(version(0, 0, 0)));
    assert_eq!(
        HelperVersion::parse("4294967295.0.10"),
        Ok(version(u32::MAX, 0, 10))
    );
    for bad in [
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.02.3",
        "1.2.-3",
        "+1.2.3",
        "1.2.3 ",
        "a.b.c",
        "4294967296.0.0",
        "1..3",
    ] {
        assert_eq!(HelperVersion::parse(bad), Err(HelperVersionError), "{bad}");
    }
    assert!(version(1, 10, 0) > version(1, 9, 9));
    assert!(version(2, 0, 0) > version(1, 99, 99));
    assert_eq!(version(1, 10, 0).to_string(), "1.10.0");
    assert_eq!(
        serde_json::to_value(version(3, 4, 5)).unwrap(),
        json!("3.4.5")
    );

    for good in [
        "gpu_optimizer.py",
        "lib/util.py",
        "_private/x-1.py",
        "a/b/c",
    ] {
        assert!(HelperPath::new(good).is_ok(), "{good}");
    }
    assert_eq!(HelperPath::new(""), Err(HelperPathError::Empty));
    assert_eq!(
        HelperPath::new("a".repeat(MAX_HELPER_PATH_BYTES + 1)),
        Err(HelperPathError::TooLong {
            max: MAX_HELPER_PATH_BYTES
        })
    );
    assert_eq!(
        HelperPath::new("lib\\util.py"),
        Err(HelperPathError::InvalidCharacter { character: '\\' })
    );
    assert_eq!(
        HelperPath::new("lib util.py"),
        Err(HelperPathError::InvalidCharacter { character: ' ' })
    );
    for bad in [
        "../x.py", "/x.py", "a//b", "a/", ".hidden", "a/./b", "a/../b", "-x",
    ] {
        assert_eq!(
            HelperPath::new(bad),
            Err(HelperPathError::InvalidComponent),
            "{bad}"
        );
    }
}

#[test]
fn the_abi_is_compatible_within_a_major_up_to_the_hosts_minor() {
    let host = HostHelperAbi::single(HelperAbi::new(1, 3));
    for minor in 0..=3 {
        assert_eq!(host.check(HelperAbi::new(1, minor)), Ok(()));
    }
    assert_eq!(
        host.check(HelperAbi::new(1, 4)),
        Err(HelperAbiRefusal::MinorTooNew {
            required: HelperAbi::new(1, 4),
            provided: HelperAbi::new(1, 3)
        })
    );
    assert_eq!(
        host.check(HelperAbi::new(2, 0)),
        Err(HelperAbiRefusal::MajorNotProvided {
            required: HelperAbi::new(2, 0),
            provided: vec![HelperAbi::new(1, 3)]
        })
    );
    assert!(matches!(
        host.check(HelperAbi::new(0, 9)),
        Err(HelperAbiRefusal::MajorNotProvided { .. })
    ));
    // A loader migrating between majors provides both.
    let migrating = HostHelperAbi::new([HelperAbi::new(2, 0), HelperAbi::new(1, 3)]).unwrap();
    assert_eq!(migrating.check(HelperAbi::new(2, 0)), Ok(()));
    assert_eq!(migrating.check(HelperAbi::new(1, 1)), Ok(()));
    assert!(migrating.check(HelperAbi::new(2, 1)).is_err());
    assert_eq!(
        migrating.provided(),
        vec![HelperAbi::new(1, 3), HelperAbi::new(2, 0)]
    );
    assert_eq!(
        HostHelperAbi::new([HelperAbi::new(1, 0), HelperAbi::new(1, 2)]),
        Err(HostAbiError::DuplicateMajor { major: 1 })
    );
    assert_eq!(HostHelperAbi::new([]), Err(HostAbiError::Empty));
    assert_eq!(HelperAbi::new(1, 3).to_string(), "1.3");
    assert!(!HelperAbiRefusal::MinorTooNew {
        required: HelperAbi::new(1, 4),
        provided: HelperAbi::new(1, 3)
    }
    .to_string()
    .is_empty());
}

#[test]
fn the_bundle_framing_is_exact_and_every_file_is_checked() {
    let bytes = encoded(version(1, 2, 0), HelperAbi::new(1, 0));
    assert_eq!(
        HelperBundle::decode(&bytes[..5]),
        Err(BundleError::Truncated)
    );
    let mut magic = bytes.clone();
    magic[0] = b'X';
    assert_eq!(HelperBundle::decode(&magic), Err(BundleError::BadMagic));
    assert_eq!(
        HelperBundle::decode(&bytes[..40]),
        Err(BundleError::Truncated)
    );
    let mut long_manifest = bytes.clone();
    long_manifest[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        HelperBundle::decode(&long_manifest),
        Err(BundleError::Manifest {
            error: ManifestError::TooLarge {
                max_bytes: MAX_MANIFEST_BYTES
            }
        })
    );
    let found = u64::try_from(bytes.len()).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        HelperBundle::decode(&trailing),
        Err(BundleError::LengthMismatch {
            expected_bytes: found,
            found_bytes: found + 1
        })
    );
    assert_eq!(
        HelperBundle::decode(&bytes[..bytes.len() - 1]),
        Err(BundleError::LengthMismatch {
            expected_bytes: found,
            found_bytes: found - 1
        })
    );
    // One flipped byte in the last file: tampered.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x20;
    match HelperBundle::decode(&tampered) {
        Err(BundleError::FileDigestMismatch {
            path: changed,
            expected,
            found,
        }) => {
            assert_eq!(changed, path("lib/util.py"));
            assert_eq!(expected, ContentKey::of(UTIL_SOURCE));
            assert_ne!(found, expected);
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
    let oversized = vec![0u8; usize::try_from(MAX_BUNDLE_BYTES).unwrap() + 1];
    assert_eq!(
        HelperBundle::decode(&oversized),
        Err(BundleError::TooLarge {
            max_bytes: MAX_BUNDLE_BYTES
        })
    );
    assert!(!BundleError::Truncated.to_string().is_empty());
}
