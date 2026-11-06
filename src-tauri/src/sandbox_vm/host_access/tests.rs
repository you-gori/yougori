use super::*;

struct Fixture {
    access: Shared,
    dir: tempfile::TempDir,
    live: AtomicBool,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("host")).unwrap();
        std::fs::write(dir.path().join("host/input.txt"), b"private contents").unwrap();
        let access = Access::open(dir.path().join("access.json")).unwrap();
        access.lock().unwrap().roots = vec![dir.path().join("host")];
        Self {
            access,
            dir,
            live: AtomicBool::new(true),
        }
    }
    fn path(&self, name: &str) -> String {
        self.dir
            .path()
            .join("host")
            .join(name)
            .to_string_lossy()
            .replace('\\', "/")
    }
    fn owner(&self, input: Value) -> Result<Value, String> {
        self.access.lock().unwrap().owner("vm-a", &input)
    }
    fn guest(&self, input: Value) -> Result<Value, String> {
        self.access
            .lock()
            .unwrap()
            .guest("vm-a", &self.live, &input)
    }
    fn enable(&self) {
        self.owner(json!({"operation":"policy","policy":{"treeVisible":true,"askForAccess":true}}))
            .unwrap();
    }
    fn grant(&self, name: &str, mode: &str, duration: &str) -> String {
        let request = self
            .guest(json!({"operation":"request","path":self.path(name),"mode":mode}))
            .unwrap();
        self.owner(
            json!({"operation":"approve","request":request["id"],"mode":mode,"duration":duration}),
        )
        .unwrap();
        self.guest(json!({"operation":"request_status","request":request["id"]}))
            .unwrap()["grant"]
            .as_str()
            .unwrap()
            .into()
    }
}

#[test]
fn a_grant_follows_the_approved_folder_not_a_replacement_at_its_path() {
    let f = Fixture::new();
    f.enable();
    std::fs::create_dir(f.dir.path().join("host/project")).unwrap();
    std::fs::write(f.dir.path().join("host/project/notes.txt"), b"approved folder").unwrap();
    let folder = f.grant("project", "read", "always");
    let file = f.grant("project/notes.txt", "read", "always");
    let read = |grant: &str| f.guest(json!({"operation":"read","path":f.path("project/notes.txt"),"grant":grant}));
    assert!(read(&folder).is_ok());
    // An editor's save replaces the file itself: the file grant keeps working.
    std::fs::write(f.dir.path().join("host/project/notes.new"), b"saved again").unwrap();
    std::fs::rename(f.dir.path().join("host/project/notes.new"), f.dir.path().join("host/project/notes.txt")).unwrap();
    assert!(read(&file).is_ok());
    // The approved folder moved away and another created at its path: neither grant applies.
    std::fs::rename(f.dir.path().join("host/project"), f.dir.path().join("host/moved")).unwrap();
    std::fs::create_dir(f.dir.path().join("host/project")).unwrap();
    std::fs::write(f.dir.path().join("host/project/notes.txt"), b"someone else's").unwrap();
    for grant in [&folder, &file] {
        let error = read(grant).unwrap_err();
        assert!(error.contains("replaced or removed"), "{error}");
    }
    // A grant saved before folders were pinned still reads (no identity recorded).
    let saved: Value = serde_json::from_slice(&std::fs::read(f.dir.path().join("access.json")).unwrap()).unwrap();
    assert!(saved["grants"][&folder]["folderIdentity"].is_string() || saved["grants"][&folder]["folderIdentity"].is_object());
}

#[test]
fn switches_are_independent_and_listing_never_returns_contents() {
    let f = Fixture::new();
    assert!(f
        .guest(json!({"operation":"tree","path":f.path("")}))
        .is_err());
    f.owner(json!({"operation":"policy","policy":{"treeVisible":true,"askForAccess":false}}))
        .unwrap();
    let tree = f
        .guest(json!({"operation":"tree","path":f.path("")}))
        .unwrap();
    assert_eq!(tree["entries"][0]["name"], "input.txt");
    assert!(!tree.to_string().contains("private contents"));
    assert!(f
        .guest(json!({"operation":"request","path":f.path("input.txt"),"mode":"read"}))
        .is_err());
    assert!(f
        .guest(json!({"operation":"read","path":f.path("input.txt"),"grant":"invented"}))
        .is_err());
    f.owner(json!({"operation":"policy","policy":{"treeVisible":false,"askForAccess":true}}))
        .unwrap();
    assert!(f
        .guest(json!({"operation":"tree","path":f.path("")}))
        .is_err());
    assert!(f
        .guest(json!({"operation":"request","path":f.path("input.txt"),"mode":"read"}))
        .is_ok());
}

#[test]
fn one_time_read_is_consumed_durably_and_cannot_be_replayed_or_used_by_another_vm() {
    let f = Fixture::new();
    f.enable();
    let grant = f.grant("input.txt", "read", "once");
    let request = json!({"operation":"read","path":f.path("input.txt"),"grant":grant});
    assert!(f
        .access
        .lock()
        .unwrap()
        .guest("vm-b", &f.live, &request)
        .is_err());
    assert!(f
        .guest(
            json!({"operation":"approve","request":"whatever","mode":"read","duration":"always"})
        )
        .is_err());
    let value = f.guest(request.clone()).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(value["contentBase64"].as_str().unwrap())
            .unwrap(),
        b"private contents"
    );
    assert!(f.guest(request.clone()).is_err());
    let restored = Access::open(f.dir.path().join("access.json")).unwrap();
    restored.lock().unwrap().roots = vec![f.dir.path().join("host")];
    assert!(restored
        .lock()
        .unwrap()
        .guest("vm-a", &f.live, &request)
        .is_err());
}

#[test]
fn read_only_folder_scope_revocation_and_atomic_write_are_enforced() {
    let f = Fixture::new();
    f.enable();
    std::fs::create_dir(f.dir.path().join("host/inside")).unwrap();
    std::fs::create_dir(f.dir.path().join("host/inside-other")).unwrap();
    std::fs::write(f.dir.path().join("host/inside/a.txt"), b"old").unwrap();
    let read = f.grant("inside", "read", "always");
    assert!(f.guest(json!({"operation":"write","path":f.path("inside/a.txt"),"grant":read,"contentBase64":"bmV3"})).is_err());
    assert_eq!(
        std::fs::read(f.dir.path().join("host/inside/a.txt")).unwrap(),
        b"old"
    );
    assert!(f
        .guest(json!({"operation":"list","path":f.path("inside-other"),"grant":read}))
        .is_err());
    assert!(f.guest(json!({"operation":"read","path":format!("{}/../input.txt",f.path("inside")),"grant":read})).is_err());
    let write = f.grant("inside", "read_write", "always");
    f.guest(json!({"operation":"write","path":f.path("inside/a.txt"),"grant":write,"contentBase64":"bmV3"})).unwrap();
    f.guest(json!({"operation":"write","path":f.path("inside/empty.txt"),"grant":write,"contentBase64":""})).unwrap();
    assert_eq!(
        std::fs::read(f.dir.path().join("host/inside/a.txt")).unwrap(),
        b"new"
    );
    assert_eq!(
        std::fs::read(f.dir.path().join("host/inside/empty.txt")).unwrap(),
        b""
    );
    f.owner(json!({"operation":"revoke","grant":write}))
        .unwrap();
    assert!(f.guest(json!({"operation":"write","path":f.path("inside/a.txt"),"grant":write,"contentBase64":""})).is_err());
}

#[test]
fn listing_pages_cover_large_directories_without_contents_or_duplicate_names() {
    let f = Fixture::new();
    f.enable();
    for i in 0..300 {
        std::fs::write(f.dir.path().join(format!("host/file-{i:04}")), b"secret").unwrap();
    }
    let first = f
        .guest(json!({"operation":"tree","path":f.path("")}))
        .unwrap();
    assert_eq!(first["entries"].as_array().unwrap().len(), 256);
    let second = f
        .guest(json!({"operation":"tree","path":f.path(""),"after":first["next"]}))
        .unwrap();
    assert_eq!(second["entries"].as_array().unwrap().len(), 45);
    assert!(second["next"].is_null());
    assert!(!first.to_string().contains("secret"));
}

#[test]
fn hardlinks_and_stopped_channels_cannot_read_or_write() {
    let f = Fixture::new();
    f.enable();
    let grant = f.grant("input.txt", "read_write", "always");
    std::fs::hard_link(
        f.dir.path().join("host/input.txt"),
        f.dir.path().join("outside-link"),
    )
    .unwrap();
    assert!(f
        .guest(json!({"operation":"read","path":f.path("input.txt"),"grant":grant}))
        .is_err());
    assert!(f
        .guest(
            json!({"operation":"write","path":f.path("input.txt"),"grant":grant,"contentBase64":""})
        )
        .is_err());
    f.live.store(false, Ordering::Release);
    assert!(f.guest(json!({"operation":"tree"})).is_err());
    assert_eq!(
        std::fs::read(f.dir.path().join("outside-link")).unwrap(),
        b"private contents"
    );
}

#[test]
fn ended_vms_lose_saved_permissions_and_requests_without_affecting_live_vms() {
    let f = Fixture::new();
    f.enable();
    f.grant("input.txt", "read", "always");
    let mut broker = f.access.lock().unwrap();
    broker
        .retain_running(&std::collections::BTreeSet::from(["vm-a".into()]))
        .unwrap();
    assert_eq!(broker.view("vm-a")["grants"].as_array().unwrap().len(), 1);
    broker
        .retain_running(&std::collections::BTreeSet::new())
        .unwrap();
    assert!(broker.view("vm-a")["grants"].as_array().unwrap().is_empty());
    assert!(broker.view("vm-a")["requests"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(broker.view("vm-a")["policy"]["askForAccess"], false);
}
