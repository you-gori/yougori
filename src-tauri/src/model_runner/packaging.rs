//! Regression coverage for the actual embedded sources and canonical workload limits.
//! Local creation/refresh use Options::validate before provisioning or persistence.
use super::{
    backends_source, clef_source, optimizer, publisher_source, registry_source, server_payload,
    server_source,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::Read;
use yougori_cli::workload::{Options, Volume};

fn helpers() -> Vec<(&'static str, String, Vec<u8>)> {
    vec![
        (
            "YOUGORI_MODEL_SERVER_SOURCE",
            server_payload(),
            include_bytes!("../model_server.py").to_vec(),
        ),
        (
            "YOUGORI_GPU_SOURCE",
            optimizer::source(),
            include_bytes!("gpu_optimizer.py").to_vec(),
        ),
        (
            "YOUGORI_CLEF_SOURCE",
            clef_source(),
            include_bytes!("adapters/clef/joint_schema_model.py").to_vec(),
        ),
        (
            "YOUGORI_PUBLISHER_SOURCE",
            publisher_source(),
            include_str!("publisher_artifacts.py")
                .replace("\r\n", "\n")
                .into_bytes(),
        ),
        (
            "YOUGORI_REGISTRY_SOURCE",
            registry_source(),
            include_str!("registry_snapshot.py")
                .replace("\r\n", "\n")
                .into_bytes(),
        ),
        (
            "YOUGORI_BACKENDS_SOURCE",
            backends_source(),
            include_str!("engine_backends.py")
                .replace("\r\n", "\n")
                .into_bytes(),
        ),
    ]
}

fn unpack(encoded: &str) -> Vec<u8> {
    let packed = STANDARD.decode(encoded).unwrap();
    let mut decoded = Vec::new();
    flate2::read::ZlibDecoder::new(packed.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    decoded
}

fn full_options() -> Options {
    let mut options = Options {
        args: Some(vec!["fixture-model".into()]),
        working_dir: Some("/workspace".into()),
        volumes: vec![Volume {
            source: "model-fixture-models".into(),
            target: "/root/.cache/huggingface".into(),
            read_only: false,
        }],
        binds: vec![Volume {
            source: "C:/fixture/weights".into(),
            target: "/yougori-model".into(),
            read_only: true,
        }],
        ..Options::default()
    };
    for (name, source, _) in helpers() {
        options.environment.insert(name.into(), source);
    }
    options
        .environment
        .insert("YOUGORI_MODEL".into(), "fixture/model".into());
    options
        .environment
        .insert("YOUGORI_MODEL_REVISION".into(), "a".repeat(40));
    options
        .environment
        .insert("YOUGORI_LOCAL_MANIFEST".into(), r#"{"files":[]}"#.into());
    for name in [
        "YOUGORI_MODEL_TOKEN",
        "YOUGORI_MODEL_ADMIN_TOKEN",
        "YOUGORI_GPU_CONTROL_TOKEN",
        "HF_TOKEN",
    ] {
        options
            .secret_environment
            .insert(name.into(), "fixture-vault-reference".into());
    }
    options
}

fn serialized_len(options: &Options) -> usize {
    serde_json::to_vec(options).unwrap().len()
}

fn sized_options(target: usize) -> Options {
    let mut options = full_options();
    for index in 0..4 {
        options
            .environment
            .insert(format!("FIXTURE_PADDING_{index}"), String::new());
    }
    let mut remaining = target
        .checked_sub(serialized_len(&options))
        .expect("current package exceeds fixture budget");
    for index in 0..4 {
        let size = remaining.min(65536);
        options
            .environment
            .insert(format!("FIXTURE_PADDING_{index}"), "x".repeat(size));
        remaining -= size;
    }
    assert_eq!(remaining, 0);
    assert_eq!(serialized_len(&options), target);
    options
}

#[test]
fn every_embedded_helper_roundtrips_exactly() {
    for (name, packed, expected) in helpers() {
        assert_eq!(unpack(&packed), expected, "changed bytes in {name}");
    }
}

#[test]
fn complete_current_helper_set_fits_canonical_options_with_metadata() {
    // Conservative superset: no existing launch needs every optional helper at once.
    // Use the actual compiled sources; no stale hard-coded compressed sizes.
    full_options().validate().unwrap();
}

#[test]
fn environment_limit_is_inclusive_and_counts_utf8_bytes() {
    let mut options = full_options();
    options
        .environment
        .insert("FIXTURE_VALUE".into(), "é".repeat(32768));
    assert_eq!(options.environment["FIXTURE_VALUE"].len(), 65536);
    options.validate().unwrap();
    options
        .environment
        .get_mut("FIXTURE_VALUE")
        .unwrap()
        .push('x');
    let error = options.validate().unwrap_err();
    assert!(error.contains("Invalid environment variable"));
    assert!(!error.contains("fixture-vault-reference"));
    assert!(!error.contains('é'));
}

#[test]
fn aggregate_limit_is_inclusive_over_actual_serialized_options() {
    let options = sized_options(256 * 1024);
    options.validate().unwrap();
    let oversized = sized_options(256 * 1024 + 1);
    assert!(oversized
        .environment
        .values()
        .all(|value| value.len() <= 65536));
    assert_eq!(
        oversized.validate().unwrap_err(),
        "Workload options exceed 256 KiB"
    );
}

#[test]
fn serialized_escape_expansion_consumes_the_aggregate_budget() {
    let mut options = sized_options(256 * 1024);
    options.validate().unwrap();
    let value = options.environment.get_mut("FIXTURE_PADDING_0").unwrap();
    let raw_bytes = value.len();
    value.replace_range(..1, "\n");
    assert_eq!(value.len(), raw_bytes);
    assert_eq!(serialized_len(&options), 256 * 1024 + 1);
    assert_eq!(
        options.validate().unwrap_err(),
        "Workload options exceed 256 KiB"
    );
}

#[test]
fn non_environment_options_share_the_same_serialized_budget() {
    let mut options = sized_options(256 * 1024);
    options.validate().unwrap();
    options.args.as_mut().unwrap()[0].push('x');
    assert_eq!(serialized_len(&options), 256 * 1024 + 1);
    assert_eq!(
        options.validate().unwrap_err(),
        "Workload options exceed 256 KiB"
    );
}

#[test]
fn remote_file_bundle_preserves_sources_and_fits_its_distinct_transport_limit() {
    // NeoCloud writes this as a file through model/run, not an environment value.
    // The remote model.py guard counts Python str characters, not UTF-8 bytes.
    let source = server_source();
    assert!(source.chars().count() <= 262144);
    let mut parts = source.splitn(5, '\n');
    for (name, expected) in [
        (
            "__YOUGORI_GPU_SOURCE__",
            include_bytes!("gpu_optimizer.py").to_vec(),
        ),
        (
            "__YOUGORI_CLEF_SOURCE__",
            include_bytes!("adapters/clef/joint_schema_model.py").to_vec(),
        ),
        (
            "__YOUGORI_PUBLISHER_SOURCE__",
            include_str!("publisher_artifacts.py")
                .replace("\r\n", "\n")
                .into_bytes(),
        ),
        (
            "__YOUGORI_BACKENDS_SOURCE__",
            include_str!("engine_backends.py")
                .replace("\r\n", "\n")
                .into_bytes(),
        ),
    ] {
        let line = parts.next().unwrap();
        let encoded = line
            .strip_prefix(&format!("{name} = '"))
            .unwrap()
            .strip_suffix('\'')
            .unwrap();
        assert_eq!(unpack(encoded), expected, "changed remote helper {name}");
    }
    assert_eq!(parts.next().unwrap(), include_str!("../model_server.py"));
}
