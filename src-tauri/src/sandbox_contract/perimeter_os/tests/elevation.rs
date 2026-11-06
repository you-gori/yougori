//! The elevation scope of a plan and of an isolation on each platform: which command or
//! API, which object, exactly the granted operations, and the platform name of every
//! identity the operations add rules for, which the digest binds.

use std::collections::BTreeSet;

use super::super::fakes::{FakeNft, FakeWfp};
use super::nft::NftBench;
use super::scenarios::{installed, Bench};
use super::wfp::WfpBench;
use super::*;
use crate::sandbox_contract::perimeter_install::IdentityKind;

/// The grant of updating the installed old rules to the new ones on `B`.
fn update_grant<B: Bench>() -> (B::Store, ElevationGrant) {
    let (installer, store, _) = installed::<B>();
    let prepared = installer
        .prepare(
            &store,
            &profile(B::PLATFORM, B::broker(), new_rules()),
            B::broker(),
        )
        .unwrap();
    let grant = prepared.grant_request();
    (store, grant)
}

/// The operations a scope of `grant` must list: each granted add and removal, then the
/// rollback of the transaction's own rules.
fn operations(grant: &ElevationGrant) -> Vec<ElevatedOperation> {
    let mut operations: Vec<ElevatedOperation> = grant
        .may_add
        .iter()
        .map(|scoped| ElevatedOperation::AddRule { scoped: *scoped })
        .collect();
    operations.extend(
        grant
            .may_remove
            .iter()
            .map(|handle| ElevatedOperation::RemoveRule { handle: *handle }),
    );
    operations.push(ElevatedOperation::RemoveTagged);
    operations
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn a_plan_scope_names_the_command_the_object_the_operations_and_the_identities() {
    let (store, grant) = update_grant::<NftBench>();
    let scope = store.elevation_scope(&grant).unwrap();
    assert_eq!(scope.platform, PerimeterPlatform::Linux);
    assert_eq!(
        scope.mechanism,
        ElevatedMechanism::Nftables {
            reads: vec![
                argv(&["nft", "-j", "list", "table", "inet", "yougori"]),
                argv(&["nft", "-j", "list", "tables"]),
            ],
            write: argv(&["nft", "-j", "-f", "-"]),
            family: "inet".to_owned(),
            table: "yougori".to_owned(),
            chain: "perimeter".to_owned(),
        }
    );
    assert_eq!(scope.plan, Some(grant.plan));
    assert_eq!(scope.tag, Some(grant.tag));
    assert_eq!(scope.operations, operations(&grant));
    assert_eq!(
        scope.operations.len(),
        grant.may_add.len() + grant.may_remove.len() + 1
    );
    assert_eq!(
        scope.identities,
        vec![ScopeIdentity {
            identity: NftBench::broker().identity,
            selector: PlatformSelector::Nftables {
                selector: NftSelector::SocketUid { uid: 961 }
            },
        }]
    );

    let (store, grant) = update_grant::<WfpBench>();
    let scope = store.elevation_scope(&grant).unwrap();
    assert_eq!(scope.platform, PerimeterPlatform::Windows);
    assert_eq!(
        scope.mechanism,
        ElevatedMechanism::Wfp {
            calls: vec![
                WfpCall::FwpmEngineOpen0,
                WfpCall::FwpmFilterEnum0,
                WfpCall::FwpmSubLayerGetByKey0,
                WfpCall::FwpmTransactionBegin0,
                WfpCall::FwpmFilterAdd0,
                WfpCall::FwpmFilterDeleteByKey0,
                WfpCall::FwpmTransactionCommit0,
            ],
            provider: WFP_PROVIDER,
            sublayer: WFP_SUBLAYER,
            layers: WfpLayer::ALL.to_vec(),
        }
    );
    assert_eq!(scope.operations, operations(&grant));
    assert_eq!(
        scope.identities,
        vec![ScopeIdentity {
            identity: WfpBench::broker().identity,
            selector: PlatformSelector::Wfp {
                selector: super::wfp::selector()
            },
        }]
    );

    // pf: a grant built by hand, since V16 does not install over pf.
    let store = super::pf::store();
    let broker = super::pf::broker();
    let grant = ElevationGrant {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::FIRST,
        },
        plan: id("plan"),
        may_add: scoped(broker.identity, &old_rules()),
        may_remove: BTreeSet::new(),
    };
    let scope = store.elevation_scope(&grant).unwrap();
    let anchor = store.anchor().as_str();
    assert_eq!(scope.platform, PerimeterPlatform::MacOs);
    assert_eq!(
        scope.mechanism,
        ElevatedMechanism::Pf {
            read: argv(&["pfctl", "-a", anchor, "-sr"]),
            write: argv(&["pfctl", "-a", anchor, "-f", "-"]),
            anchor: anchor.to_owned(),
        }
    );
    assert_eq!(scope.operations, operations(&grant));
    assert_eq!(
        scope.identities,
        vec![ScopeIdentity {
            identity: broker.identity,
            selector: PlatformSelector::Pf {
                selector: PfSelector::User { uid: 498 }
            },
        }]
    );
}

#[test]
fn the_scope_digest_binds_the_plan_and_the_object() {
    let (store, grant) = update_grant::<NftBench>();
    let digest = |store: &NftStore<FakeNft>, grant: &ElevationGrant| {
        store.elevation_scope(grant).unwrap().digest().unwrap()
    };
    let scope = digest(&store, &grant);
    assert_eq!(digest(&store, &grant), scope);
    let mut other = grant.clone();
    other.plan = id("another plan");
    assert_ne!(digest(&store, &other), scope);
    let mut fewer = grant.clone();
    fewer.may_remove.clear();
    assert_ne!(digest(&store, &fewer), scope);
    let (wfp, _) = update_grant::<WfpBench>();
    // A removal-only grant names no identity, so both stores accept it.
    let mut on_windows = grant.clone();
    on_windows.may_add.clear();
    assert_ne!(
        wfp.elevation_scope(&on_windows).unwrap().digest().unwrap(),
        digest(&store, &on_windows)
    );
}

/// The same grant under another platform name for the broker yields another scope and
/// digest (review R10: uid 961 and uid 1000 gave one digest).
#[test]
fn the_scope_digest_binds_each_identitys_platform_name() {
    let (store, grant) = update_grant::<NftBench>();
    let broker = NftBench::broker();
    let rebound =
        |selector| NftStore::new(FakeNft::default(), vec![Binding { broker, selector }]).unwrap();
    let other = rebound(NftSelector::SocketUid { uid: 1000 });
    assert_ne!(
        store.elevation_scope(&grant).unwrap().digest().unwrap(),
        other.elevation_scope(&grant).unwrap().digest().unwrap()
    );
    assert_ne!(
        store
            .isolation_scope(broker.identity)
            .unwrap()
            .digest()
            .unwrap(),
        other
            .isolation_scope(broker.identity)
            .unwrap()
            .digest()
            .unwrap()
    );

    // Cgroup paths, accounts, namespaces: each name gives its own digest.
    let isolation = |kind, selector| {
        let broker = BrokerIdentity {
            kind,
            identity: broker.identity,
        };
        NftStore::new(FakeNft::default(), vec![Binding { broker, selector }])
            .unwrap()
            .isolation_scope(broker.identity)
            .unwrap()
            .digest()
            .unwrap()
    };
    let cgroup = |path: &str, uid| NftSelector::Cgroup {
        path: CgroupPath::new(path).unwrap(),
        uid,
    };
    let namespace = |name: &str| NftSelector::Namespace {
        name: NamespaceName::new(name).unwrap(),
    };
    let digests = BTreeSet::from([
        isolation(IdentityKind::Cgroup, cgroup("yougori.slice/a.scope", 961)),
        isolation(IdentityKind::Cgroup, cgroup("yougori.slice/b.scope", 961)),
        isolation(IdentityKind::Cgroup, cgroup("yougori.slice/a.scope", 962)),
        isolation(IdentityKind::NetworkNamespace, namespace("yougori-a")),
        isolation(IdentityKind::NetworkNamespace, namespace("yougori-b")),
    ]);
    assert_eq!(digests.len(), 5);

    // WFP: another SID, or another service carrying it, is another scope.
    let wfp_broker = WfpBench::broker();
    let wfp_digest = |selector| {
        WfpStore::new(
            FakeWfp::default(),
            vec![Binding {
                broker: wfp_broker,
                selector,
            }],
        )
        .unwrap()
        .isolation_scope(wfp_broker.identity)
        .unwrap()
        .digest()
        .unwrap()
    };
    let service = |name: &str, sid: &str| WfpSelector::ServiceSid {
        service: ServiceName::new(name).unwrap(),
        sid: Sid::parse(sid).unwrap(),
    };
    let digests = BTreeSet::from([
        wfp_digest(service("YougoriBroker", "S-1-5-80-1-2-3-4-5")),
        wfp_digest(service("YougoriBroker", "S-1-5-80-1-2-3-4-6")),
        wfp_digest(service("OtherBroker", "S-1-5-80-1-2-3-4-5")),
    ]);
    assert_eq!(digests.len(), 3);
}

#[test]
fn a_scope_for_an_identity_the_store_does_not_bind_is_refused() {
    let (store, mut grant) = update_grant::<NftBench>();
    let stranger = id("stranger");
    grant.may_add.insert(ScopedRule {
        identity: stranger,
        rule: allow("192.0.2.0", 24, 443),
    });
    assert_eq!(
        store.elevation_scope(&grant),
        Err(BindingError::Unbound { identity: stranger })
    );
    assert_eq!(
        store.isolation_scope(stranger),
        Err(BindingError::Unbound { identity: stranger })
    );
}

#[test]
fn an_isolation_scope_names_provisioning_and_the_identity() {
    let store = NftBench::store();
    let identity = NftBench::broker().identity;
    let scope = store.isolation_scope(identity).unwrap();
    assert_eq!(scope.plan, None);
    assert_eq!(scope.tag, None);
    assert_eq!(
        scope.operations,
        vec![
            ElevatedOperation::ProvisionObject,
            ElevatedOperation::Isolate { identity }
        ]
    );
    assert_eq!(scope.identities.len(), 1);

    let store = WfpBench::store();
    let scope = store.isolation_scope(WfpBench::broker().identity).unwrap();
    let ElevatedMechanism::Wfp { calls, layers, .. } = &scope.mechanism else {
        panic!("unexpected {:?}", scope.mechanism);
    };
    assert!(calls.contains(&WfpCall::FwpmProviderAdd0));
    assert!(calls.contains(&WfpCall::FwpmSubLayerAdd0));
    assert!(!calls.contains(&WfpCall::FwpmFilterDeleteByKey0));
    assert_eq!(*layers, WfpLayer::ALL.to_vec());

    let store = super::pf::store();
    let scope = store
        .tcp_udp_deny_scope(super::pf::broker().identity)
        .unwrap();
    assert_eq!(scope.platform, PerimeterPlatform::MacOs);
    assert_eq!(scope.operations.len(), 2);
}
