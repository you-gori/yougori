//! The read-only adapters for cloud compute and object storage.
//!
//! Every connector in here answers `alters_anything` with no, and the reason is a type rather than
//! a policy. `Connector::plan` takes a `Request`, `Request` carries a `Subject`, and `Subject::new`
//! refuses anything without an email in it. That is right for the thing this trait was built for,
//! which is giving or taking back one named person's access at a provider. "List the machines this
//! credential reaches" is about nobody, and "create an instance for the grid" is about nobody
//! either, so neither can be made into an honest `Request`.
//!
//! There were two ways out of that. Widen `Request` so a plan can be about no person, which would
//! take away the thing that stops a connector being handed somebody it was never told about. Or
//! keep these connectors read-only, which is what `docs/grid-core/adapters.md` has said from the
//! first version of it: read-only first. This is the second.
//!
//! So each of these makes a plan whose steps all read, which `cleared` refuses to carry out, and
//! implements `apply`, `reconcile` and `revoke` by saying so in the one sentence `reads_only`
//! holds. There is no path through any of them that changes a tenant, and that is a fact about
//! the calls rather than a promise in this comment.
//!
//! What they do is `discover`, which is the first thing an administrator runs on a new connection
//! and the thing that answers "does this credential work and what does it reach", and `observe`,
//! which says what is true at the provider now. Both are worth shipping on their own.
//!
//! Every one of them is exercised against a server on this computer that answers the way the
//! provider's published API documents, and against nothing else. There is no tenant here, no
//! vendor library and no credential, and none of these has ever met a real account.
use super::wire::{xml_all, xml_text, Call, Reply, Wire};
use super::{admits, reads_only, Answer, Checked, Connector, Discovery, Found, Note, Notes, Outcome, Plan, Rehearsal, Request, Seen, Settings, Step, Ticket, Trouble};
use crate::core::audit::Decision;

/// Which cloud service one of these is pointed at.
///
/// One type for all of them rather than seven, because they differ in three things only: which
/// request lists what the credential reaches, how the answer is read, and what the thing found is
/// called. Everything else, including the whole of the read-only rule, is the same in all seven,
/// and seven copies of it is seven places for it to drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// Amazon EC2 instances, through the Query API with XML answers.
    AmazonCompute,
    /// Amazon ECS clusters, through the JSON API with an `X-Amz-Target` header.
    AmazonContainers,
    /// Amazon EKS clusters, through the REST API.
    AmazonKubernetes,
    /// Objects in an S3 bucket, through the REST API with XML listings.
    AmazonStorage,
    /// Azure virtual machines, through Azure Resource Manager.
    AzureCompute,
    /// Blobs in an Azure Storage container, through the Blob service.
    AzureStorage,
    /// Nodes in a Kubernetes cluster, through the API server.
    Kubernetes,
    /// Instances on an OpenStack cloud, through Nova.
    OpenStack,
}

impl Service {
    /// The registry row this is. A connector naming a row cannot claim more than the documentation
    /// does, because the row and the document are rendered from one table.
    pub fn row(self) -> &'static str {
        match self {
            Service::AmazonCompute => "Amazon EC2",
            Service::AmazonContainers => "Amazon ECS",
            Service::AmazonKubernetes => "Amazon EKS",
            Service::AmazonStorage => "S3 and S3-compatible object storage",
            Service::AzureCompute => "Azure virtual machines",
            Service::AzureStorage => "Azure Blob Storage",
            Service::Kubernetes => "Kubernetes",
            Service::OpenStack => "OpenStack",
        }
    }

    /// What one thing found at this provider is called, in the provider's own word for it.
    fn kind(self) -> &'static str {
        match self {
            Service::AmazonCompute | Service::AzureCompute | Service::OpenStack => "machine",
            Service::AmazonContainers | Service::AmazonKubernetes => "cluster",
            Service::AmazonStorage | Service::AzureStorage => "object",
            Service::Kubernetes => "node",
        }
    }

    /// The settings this connection cannot work without, named in the words an administrator saw
    /// when they entered them.
    fn needs(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Service::AmazonCompute | Service::AmazonContainers | Service::AmazonKubernetes => &[("region", "region")],
            Service::AmazonStorage => &[("region", "region"), ("bucket", "bucket")],
            Service::AzureCompute => &[("subscriptionId", "subscription ID"), ("resourceGroup", "resource group")],
            Service::AzureStorage => &[("account", "storage account"), ("container", "container")],
            Service::Kubernetes => &[],
            Service::OpenStack => &[],
        }
    }

}

/// One cloud service, read only.
pub struct ReadOnlyCloud {
    service: Service,
    settings: Settings,
    wire: Box<dyn Wire>,
    notes: Notes,
}

impl std::fmt::Debug for ReadOnlyCloud {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ReadOnlyCloud").field("service", &self.service).field("destination", &self.wire.destination()).field("settings", &self.settings.names()).finish()
    }
}

impl ReadOnlyCloud {
    pub fn new(service: Service, settings: Settings, wire: Box<dyn Wire>) -> ReadOnlyCloud {
        ReadOnlyCloud { service, settings, wire, notes: Notes::new() }
    }

    /// What the connection was told, or which identifier is missing.
    fn complete(&self) -> Result<(), Trouble> {
        for (field, what) in self.service.needs() {
            self.settings.needed(field, what)?;
        }
        Ok(())
    }

    fn record(&self, at: i64, action: &str, decision: Decision, reason: &str) {
        self.notes.keep(Note::new(self.service.row(), at, action, decision, reason));
    }

    /// One request, with the version of the credential that authorised it kept for the note.
    async fn ask(&self, ticket: &Ticket, call: Call, action: &str, now: i64) -> Result<Reply, Trouble> {
        match self.wire.send(ticket, call, now).await {
            Ok(reply) if reply.ok() => {
                self.record(now, action, Decision::Allowed, &self.with_version(&reply.said()));
                Ok(reply)
            }
            Ok(reply) => {
                let said = reply.said();
                self.record(now, action, Decision::Refused, &said);
                Err(Trouble::Refused(said))
            }
            Err(trouble) => {
                self.record(now, action, Decision::Refused, trouble.say());
                Err(trouble)
            }
        }
    }

    /// A note, with which version of the credential authorised the request it describes. That is
    /// what makes a rotation visible in the history: the value never appears, the version does.
    fn with_version(&self, said: &str) -> String {
        match self.wire.version_used() {
            Some(version) => format!("{said} (credential version {version})"),
            None => said.to_owned(),
        }
    }

    /// The one request that lists what this credential reaches, and how to read the answer.
    fn listing(&self) -> Result<Call, Trouble> {
        Ok(match self.service {
            Service::AmazonCompute => Call::of("POST", "/").with("Action", "DescribeInstances").with("Version", "2016-11-15"),
            Service::AmazonContainers => Call::of("POST", "/").header("x-amz-target", "AmazonEC2ContainerServiceV20141113.ListClusters").json(serde_json::json!({})),
            Service::AmazonKubernetes => Call::get("/clusters"),
            Service::AmazonStorage => Call::get(&format!("/{}", self.settings.needed("bucket", "bucket")?)).with("list-type", "2").with("max-keys", "100"),
            Service::AzureCompute => Call::get(&format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines",
                self.settings.needed("subscriptionId", "subscription ID")?,
                self.settings.needed("resourceGroup", "resource group")?
            ))
            .with("api-version", AZURE_COMPUTE_VERSION),
            Service::AzureStorage => Call::get(&format!("/{}", self.settings.needed("container", "container")?)).with("restype", "container").with("comp", "list"),
            Service::Kubernetes => Call::get("/api/v1/nodes"),
            Service::OpenStack => Call::get("/servers/detail"),
        })
    }

    /// What the provider said it reaches, as rows an administrator can read.
    fn read_listing(&self, reply: &Reply) -> Vec<Found> {
        let kind = self.service.kind().to_owned();
        let found = |id: String, description: String| Found { kind: kind.clone(), id, description };
        match self.service {
            Service::AmazonCompute => {
                let text = reply.text();
                let states = xml_all(&text, "instanceState");
                xml_all(&text, "instanceId")
                    .into_iter()
                    .enumerate()
                    .map(|(index, id)| {
                        let state = states.get(index).and_then(|state| xml_text(state, "name")).unwrap_or_else(|| "state not reported".into());
                        found(id, state)
                    })
                    .collect()
            }
            Service::AmazonContainers => reply.json()["clusterArns"].as_array().into_iter().flatten().filter_map(|arn| arn.as_str()).map(|arn| found(arn.to_owned(), "an ECS cluster".into())).collect(),
            Service::AmazonKubernetes => reply.json()["clusters"].as_array().into_iter().flatten().filter_map(|name| name.as_str()).map(|name| found(name.to_owned(), "an EKS cluster".into())).collect(),
            Service::AmazonStorage => {
                let text = reply.text();
                xml_all(&text, "Contents")
                    .into_iter()
                    .filter_map(|entry| {
                        let key = xml_text(&entry, "Key")?;
                        let size = xml_text(&entry, "Size").unwrap_or_else(|| "size not reported".into());
                        Some(found(key, format!("{size} bytes")))
                    })
                    .collect()
            }
            Service::AzureCompute => reply.json()["value"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|machine| {
                    let name = machine["name"].as_str()?;
                    let size = machine["properties"]["hardwareProfile"]["vmSize"].as_str().unwrap_or("size not reported");
                    Some(found(name.to_owned(), size.to_owned()))
                })
                .collect(),
            Service::AzureStorage => {
                let text = reply.text();
                xml_all(&text, "Blob")
                    .into_iter()
                    .filter_map(|entry| {
                        let name = xml_text(&entry, "Name")?;
                        let size = xml_text(&entry, "Content-Length").unwrap_or_else(|| "size not reported".into());
                        Some(found(name, format!("{size} bytes")))
                    })
                    .collect()
            }
            Service::Kubernetes => reply.json()["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|node| {
                    let name = node["metadata"]["name"].as_str()?;
                    let ready = node["status"]["conditions"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|condition| condition["type"] == "Ready")
                        .and_then(|condition| condition["status"].as_str())
                        .unwrap_or("readiness not reported");
                    Some(found(name.to_owned(), format!("ready: {ready}")))
                })
                .collect(),
            Service::OpenStack => reply.json()["servers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|server| {
                    let name = server["name"].as_str()?;
                    let status = server["status"].as_str().unwrap_or("status not reported");
                    Some(found(name.to_owned(), status.to_owned()))
                })
                .collect(),
        }
    }

    /// The steps a plan would take. Every one of them reads, which is what makes this connector
    /// unable to be carried out at all: `cleared` refuses a plan with no altering step.
    fn steps(&self, target: &str) -> Vec<Step> {
        vec![
            Step::reading(&format!("ask {} what this credential reaches", self.service.row())),
            Step::reading(&format!("read {target} and report what the provider says is true now")),
            Step::reading(&format!("change nothing: {} is a read-only connector in this grid", self.service.row())),
        ]
    }

    /// What this connection is pointed at, in words.
    fn target(&self) -> Result<String, Trouble> {
        Ok(match self.service {
            Service::AmazonCompute => format!("the instances in {}", self.settings.needed("region", "region")?),
            Service::AmazonContainers => format!("the ECS clusters in {}", self.settings.needed("region", "region")?),
            Service::AmazonKubernetes => format!("the EKS clusters in {}", self.settings.needed("region", "region")?),
            Service::AmazonStorage => format!("the bucket {}", self.settings.needed("bucket", "bucket")?),
            Service::AzureCompute => format!("the virtual machines in resource group {}", self.settings.needed("resourceGroup", "resource group")?),
            Service::AzureStorage => format!("the container {}", self.settings.needed("container", "container")?),
            Service::Kubernetes => "the nodes of this cluster".to_owned(),
            Service::OpenStack => "the instances of this project".to_owned(),
        })
    }

    /// Everything checked before an operation naming a plan.
    fn fits(&self, ticket: &Ticket, plan: &Plan, now: i64) -> Result<(), Trouble> {
        admits(ticket, self.wire.destination(), now)?;
        self.complete()?;
        if plan.connector() != self.service.row() {
            return Err(Trouble::NotAllowed(format!("This plan is for {}, and this connector is {}", plan.connector(), self.service.row())));
        }
        if plan.credential_id() != ticket.credential_id() {
            return Err(Trouble::NotAllowed("This plan was made for another credential. Make it again with the permission you hold.".into()));
        }
        Ok(())
    }
}

/// Which version of the Azure Resource Manager compute API these requests are written against.
pub const AZURE_COMPUTE_VERSION: &str = "2024-07-01";

impl Connector for ReadOnlyCloud {
    fn integration(&self) -> &'static str {
        self.service.row()
    }

    fn destination(&self) -> &str {
        self.wire.destination()
    }

    fn alters_anything(&self) -> bool {
        false
    }

    fn discover<'a>(&'a self, ticket: &'a Ticket, now: i64) -> Answer<'a, Discovery> {
        Box::pin(async move {
            admits(ticket, self.wire.destination(), now)?;
            self.complete()?;
            let target = self.target()?;
            let reply = self.ask(ticket, self.listing()?, "discover", now).await?;
            let reached = self.read_listing(&reply);
            Ok(Discovery { note: format!("Reaches {target}: {} found. This connection reads and changes nothing.", reached.len()), reached })
        })
    }

    fn plan(&self, ticket: &Ticket, request: &Request, now: i64) -> Result<Plan, Trouble> {
        admits(ticket, self.wire.destination(), now)?;
        self.complete()?;
        let target = self.target()?;
        Plan::new(self.service.row(), ticket, request.change, request.about.clone(), &target, self.steps(&target))
    }

    fn validate<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Checked> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            self.ask(ticket, self.listing()?, "validate", now).await?;
            Ok(Checked::passed(plan, now))
        })
    }

    fn dry_run<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Rehearsal> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            let reply = self.ask(ticket, self.listing()?, "dry run", now).await?;
            let reached = self.read_listing(&reply);
            Ok(Rehearsal {
                plan: plan.clone(),
                reached: true,
                note: format!("{} reached, {} found, and nothing would be changed: every step of this plan reads.", self.service.row(), reached.len()),
            })
        })
    }

    fn observe<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Seen> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            let reply = self.ask(ticket, self.listing()?, "observe", now).await?;
            let reached = self.read_listing(&reply);
            // What this connector can say is what the provider holds, not whether one person has
            // anything, because none of these APIs is about a person at all. Saying nothing is the
            // honest answer and the note says why rather than leaving an administrator to guess.
            Ok(Seen {
                holds: None,
                note: format!(
                    "{} has {} {}{} right now. Whether {} holds anything is not something this says: {} is about machines and objects, not about people.",
                    plan.target(),
                    reached.len(),
                    self.service.kind(),
                    if reached.len() == 1 { "" } else { "s" },
                    plan.about().email(),
                    self.service.row()
                ),
            })
        })
    }

    fn apply<'a>(&'a self, _ticket: &'a Ticket, _plan: &'a Plan, _checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.record(now, "apply", Decision::Refused, "this connector only reads");
            Err(reads_only(self.service.row()))
        })
    }

    fn reconcile<'a>(&'a self, _ticket: &'a Ticket, _plan: &'a Plan, _checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.record(now, "reconcile", Decision::Refused, "this connector only reads");
            Err(reads_only(self.service.row()))
        })
    }

    fn revoke<'a>(&'a self, _ticket: &'a Ticket, _plan: &'a Plan, _checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.record(now, "revoke", Decision::Refused, "this connector only reads");
            Err(reads_only(self.service.row()))
        })
    }

    fn export_audit(&self) -> Vec<Note> {
        self.notes.take(self.service.row())
    }
}

/// Whether every service this module reaches has a registry row saying what it really is. A
/// connector that outgrew its row, or a row quietly improved, fails here rather than in a
/// customer's reading of the documentation.
pub fn rows_are_honest() -> Result<(), String> {
    for service in [
        Service::AmazonCompute,
        Service::AmazonContainers,
        Service::AmazonKubernetes,
        Service::AmazonStorage,
        Service::AzureCompute,
        Service::AzureStorage,
        Service::Kubernetes,
        Service::OpenStack,
    ] {
        let row = service.row();
        let found = super::registry::find(row).ok_or_else(|| format!("{row} has no row in the registry"))?;
        if found.state != super::registry::State::MockTested {
            return Err(format!("{row} is a connector exercised against a loopback server, and its row says {}", found.state.name()));
        }
        if !found.maps_to.contains("Read") && !found.evidence.contains("Read") && !found.evidence.contains("read") {
            return Err(format!("{row} only reads, and its row does not say so"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
