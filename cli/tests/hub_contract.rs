//! The CLI's Hub client against the real website server: the bundle digest, the review computed
//! from downloaded files, search and clone counting must agree with the server's own code.
//!
//! Run with the website checkout available. The runner starts its actual server with an
//! in-memory database, seeds examples/hub/hello-site, runs this test and closes the server:
//!
//! ```text
//! node scripts/test-hub-contract.mjs PATH/TO/YougoriWebsite
//! ```
use std::collections::BTreeMap;
use yougori_cli::hub::{client, format, refs, review};

#[tokio::test]
#[ignore = "needs the website checkout; run scripts/test-hub-contract.mjs"]
async fn the_cli_downloads_checks_and_reviews_a_template_from_the_real_hub_server() {
    let base = std::env::var("YOUGORI_HUB_CONTRACT_URL").expect("set YOUGORI_HUB_CONTRACT_URL to the fixture's address");
    let site = client::Site::at(&base).expect("a local website address is allowed");
    let reference = refs::parse("hub/yougori/hello-site", &base).expect("a Hub reference");
    let saved = tempfile::tempdir().unwrap();
    let cache = client::Cache { root: saved.path().to_path_buf() };

    // Download and check every file and the version digest the server computed.
    let obtained = client::obtain(&site, &cache, &reference).await.expect("the real bundle passes every check");
    let bundle = &obtained.bundle;
    assert_eq!(bundle.version, "1.0.0");
    assert!(bundle.verified, "the fixture publishes as the owner account");
    for path in ["yougori-template.yaml", "yougori.yaml", "README.md", "site/server.py", "tools/httpie/yougori-tool.yaml"] {
        assert!(bundle.files.contains_key(path), "{path} arrived");
    }
    let page = obtained.detail.as_ref().expect("the page data");
    assert_eq!(page["version"]["digest"].as_str(), Some(bundle.digest.as_str()));
    assert_eq!(yougori_cli::hub::scan::digest_of(&bundle.files), bundle.digest);

    // The checked copy is reused, and a pinned version resolves to the same files.
    let again = client::obtain(&site, &cache, &reference.at("1.0.0")).await.expect("the saved copy");
    assert_eq!(again.bundle.digest, bundle.digest);

    // The review is built from the downloaded files on this computer.
    let folder = format::template(&bundle.files).expect("the example is a valid template");
    let mut tools = BTreeMap::new();
    tools.insert("tools/httpie".to_owned(), format::tool(&bundle.files, "tools/httpie").expect("the bundled tool is valid"));
    let local = review::template(&folder, &[], &tools);
    assert_eq!(local["environments"][0]["name"], "web");
    assert_eq!(local["environments"][0]["image"], "python:3.12-slim");
    assert!(local["public"].as_array().is_some_and(|public| public.iter().any(|entry| entry["environment"] == "web" && entry["port"] == 8080)), "{local}");
    assert!(local["tools"].as_array().is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "httpie")), "{local}");

    // Search finds it; clones count each computer once.
    let found = site.search("hello", None, None, None).await.expect("search");
    assert_eq!(found["items"][0]["ref"], "yougori/hello-site");
    let first = site.count_clone(&reference, "1.0.0", "contract-install-000001").await;
    assert!(first.is_some());
    assert_eq!(site.count_clone(&reference, "1.0.0", "contract-install-000001").await, first);
    assert_eq!(site.count_clone(&reference, "1.0.0", "contract-install-000002").await, first.map(|n| n + 1));
}

/// Publishes a package through the website's actual upload API, the way the CLI's publish does,
/// with the review the CLI computed. The token names the runner's publisher account and exists
/// only in its in-memory database.
async fn publish_fixture(base: &str, token: &str, meta: serde_json::Value, files: &yougori_cli::hub::scan::Files) -> Result<(), String> {
    use base64::Engine;
    let client = reqwest::Client::new();
    let call = |path: String, body: serde_json::Value| {
        let client = client.clone();
        let token = token.to_owned();
        async move {
            let response = client.post(format!("{base}{path}")).bearer_auth(token).json(&body).send().await.map_err(|e| e.to_string())?;
            let status = response.status();
            let value: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            if !status.is_success() {
                return Err(format!("{path}: {} ({})", value["error"].as_str().unwrap_or("?"), value["code"].as_str().unwrap_or("?")));
            }
            Ok(value)
        }
    };
    let mut body = meta;
    body["publisher"] = serde_json::json!("yougori");
    body["files"] = serde_json::json!(files.iter().map(|(path, bytes)| serde_json::json!({"path": path, "bytes": bytes.len(), "sha256": yougori_cli::hub::scan::sha256_hex(bytes)})).collect::<Vec<_>>());
    let started = call("/api/hub/uploads".into(), body).await?;
    let id = started["upload"]["id"].as_str().ok_or("no upload id")?.to_owned();
    let content: Vec<serde_json::Value> = files.iter().map(|(path, bytes)| serde_json::json!({"path": path, "content": base64::engine::general_purpose::STANDARD.encode(bytes)})).collect();
    call(format!("/api/hub/uploads/{id}/files"), serde_json::json!({"files": content})).await?;
    call(format!("/api/hub/uploads/{id}/finish"), serde_json::json!({})).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "needs the website checkout; run scripts/test-hub-contract.mjs"]
async fn the_cli_publishes_its_real_reviews_in_both_formats_and_reads_them_back() {
    use yougori_cli::hub::{plan, scan};
    let base = std::env::var("YOUGORI_HUB_CONTRACT_URL").expect("set YOUGORI_HUB_CONTRACT_URL to the fixture's address");
    let token = std::env::var("YOUGORI_HUB_CONTRACT_TOKEN").expect("set YOUGORI_HUB_CONTRACT_TOKEN to the fixture's publisher token");
    let site = client::Site::at(&base).expect("a local website address is allowed");
    let saved = tempfile::tempdir().unwrap();
    let cache = client::Cache { root: saved.path().to_path_buf() };
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub");

    // A format 2 package with the review the CLI builds for it (plan::published_review).
    let collected = scan::collect(&examples.join("host-my-app")).expect("the package reads");
    let checked = plan::check_files(&collected.files).unwrap_or_else(|p| panic!("{}", plan::problems_text("host-my-app", &p)));
    let package = yougori_setup::plan::Package { checked: checked.clone(), components: Default::default(), item: Some("yougori/host-my-app".into()), digest: Some(scan::digest_of(&collected.files)) };
    let v2_local = review::template_v2(&package, &[]).expect("the review is written");
    assert_eq!(v2_local["format"], 2);
    assert_eq!(review::shape_problem(&v2_local), None, "the website accepts the review as it is");
    let template = &checked.template;
    let meta = serde_json::json!({
        "kind": "template", "name": template.name(), "version": template.version(), "title": template.title(), "summary": template.summary,
        "license": template.license, "topics": template.topics, "changelog": template.changelog, "manifest": template.manifest(), "review": v2_local,
    });
    publish_fixture(&base, &token, meta, &collected.files).await.expect("the website accepts the CLI's format 2 upload");
    let reference = refs::parse("hub/yougori/host-my-app", &base).unwrap();
    let obtained = client::obtain(&site, &cache, &reference).await.expect("the published format 2 package downloads and checks");
    assert_eq!(obtained.bundle.digest, scan::digest_of(&collected.files));
    let page = obtained.detail.as_ref().expect("the page data");
    let page_review = &page["version"]["review"];
    assert_eq!(page_review["format"], 2, "the website stored the format 2 review");
    let downloaded = plan::check_files(&obtained.bundle.files).expect("the downloaded files check");
    let downloaded = yougori_setup::plan::Package { checked: downloaded, components: Default::default(), item: Some("yougori/host-my-app".into()), digest: Some(obtained.bundle.digest.clone()) };
    let v2_again = review::template_v2(&downloaded, &[]).expect("the review is written");
    assert!(!review::differs(&v2_again, page_review), "F12: the page's review is the one the files give");
    let mut faked = page_review.clone();
    faked["resources"] = serde_json::json!([]);
    assert!(review::differs(&v2_again, &faked), "a page that misstates the resources is caught");
    let mut faked_grant = page_review.clone();
    faked_grant["warnings"] = serde_json::json!([]);
    assert!(review::differs(&v2_again, &faked_grant), "a page that drops a warning is caught");

    // A format 1 package with the CLI's real format 1 review, as a new version of the seeded one.
    let mut v1_files = scan::collect(&examples.join("hello-site")).expect("the example reads").files;
    let marker = String::from_utf8(v1_files["yougori-template.yaml"].clone()).unwrap().replacen("version: 1.0.0", "version: 1.0.1", 1);
    v1_files.insert("yougori-template.yaml".into(), marker.into_bytes());
    let folder = format::template(&v1_files).expect("the example is a valid template");
    let mut tools = BTreeMap::new();
    tools.insert("tools/httpie".to_owned(), format::tool(&v1_files, "tools/httpie").expect("the bundled tool is valid"));
    let v1_local = review::template(&folder, &[], &tools);
    assert_eq!(v1_local["format"], 1);
    let template = &folder.template;
    let meta = serde_json::json!({
        "kind": "template", "name": template.name(), "version": "1.0.1", "title": template.title(), "summary": template.summary,
        "license": template.license, "topics": template.topics, "changelog": template.changelog, "manifest": template.manifest(), "review": v1_local,
    });
    publish_fixture(&base, &token, meta, &v1_files).await.expect("the website accepts the CLI's format 1 upload");
    let pinned = refs::parse("hub/yougori/hello-site@1.0.1", &base).unwrap();
    let newer = client::obtain(&site, &cache, &pinned).await.expect("the new version downloads");
    let page_v1 = &newer.detail.as_ref().unwrap()["version"]["review"];
    assert_ne!(page_v1["format"], 2, "a format 1 package keeps a format 1 review");
    let v1_again = review::template(&format::template(&newer.bundle.files).unwrap(), &[], &tools);
    assert!(!review::differs(&v1_again, page_v1), "F13: a format 1 page with the real review matches the files");

    // F13: old and new review formats are compared on the grants both write, never skipped.
    let seeded = client::obtain(&site, &cache, &refs::parse("hub/yougori/hello-site@1.0.0", &base).unwrap()).await.expect("the seeded version");
    let stub = &seeded.detail.as_ref().unwrap()["version"]["review"];
    assert!(review::differs(&v1_again, stub), "a page whose review leaves grants out differs from the files");
    assert!(review::differs(&v1_local, page_review), "a format 1 review of one package differs from a format 2 page of another");
    assert!(review::differs(&v2_local, page_v1), "a format 2 review of one package differs from a format 1 page of another");
    let mut unknown = page_review.clone();
    unknown["format"] = serde_json::json!(9);
    assert!(!review::differs(&v2_local, &unknown), "a review in a format this Yougori does not know is not compared part by part");

    // A format 2 upload without a format 2 review is refused by the website with its code.
    let mut manifest = checked.template.manifest();
    manifest["version"] = serde_json::json!("9.9.9");
    let bad = serde_json::json!({
        "kind": "template", "name": "host-my-app", "version": "9.9.9", "title": "x", "summary": "x", "license": "MIT", "topics": [],
        "manifest": manifest, "review": {"environments": []},
    });
    let refused = publish_fixture(&base, &token, bad, &collected.files).await.unwrap_err();
    assert!(refused.contains("review_required"), "{refused}");
}
