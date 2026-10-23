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
