use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Method {
    pub name: &'static str,
    pub summary: &'static str,
    /// `?` marks optional fields. Complex object examples come from the actual
    /// backend request shape, not an alternative configuration/state format.
    pub parameters: &'static str,
    pub example: Value,
    pub mutating: bool,
    pub confirmation: Option<&'static str>,
}

pub fn methods() -> Vec<Method> {
    let mut list = Vec::new();
    macro_rules! method {
        ($name:ident, $summary:literal, $params:literal, $example:expr, $write:expr, $confirm:expr) => {
            list.push(Method {
                name: stringify!($name),
                summary: $summary,
                parameters: $params,
                example: $example,
                mutating: $write,
                confirmation: $confirm,
            });
        };
    }
    // The grids namespace. Each noun's verbs, and the fields each takes, are read from the table
    // the CLI parses (see `grids_summary`), so the schema and the command cannot disagree.
    macro_rules! grids_method {
        ($name:ident, $noun:literal, $about:literal, $notes:literal, $example:expr) => {
            list.push(Method {
                name: stringify!($name),
                summary: grids_summary($noun, $about, $notes),
                parameters: "grid?:string request:object",
                example: $example,
                mutating: true,
                confirmation: None,
            });
        };
    }
    let env = json!({"environmentId":"env-ID"});
    method!(swarm_dispatch, "Prepare private local Swarm Mining workers; debug builds also accept developmentModel {workerId, modelEnvironmentId?, confirmed:true} to select an owned API relay for a paused private test worker or restore its local model. External model context requires explicit confirmation. Browse published metadata and apply for exact-version publisher approval without accepting work, review and explicitly accept bounty offers, immutable publisher source authorization, responsible use rules and direct-payment risk, talk to your own agent, and manage worker lifecycle. Acceptance requires confirmed:true, rulesAccepted:true, rulesVersion, rulesDigest, authorizationAccepted:true, authorizationDigest and directPaymentAccepted:true from the exact offer. Publisher promises USDC and pays externally; Yougori never funds, holds or transfers new bounty rewards. Legacy obligations require manual resolution. Authorized local defensive research only; open source modification rights remain. Worker channel credentials stay in the engine; participants cannot read raw agent channels through human sessions; bounty publishers have scoped read-only website access for versions that explicitly disclose it.", "request:object", json!({"request":{"action":"workers"}}), true, None);
    method!(model_registry_request, "Read or manage model publications, versions and wallet access grants using this computer's signed-in account.", "path:string body?:object", json!({"path":"/models?mine=1"}), true, None);
    method!(model_registry_connect, "Connect a publisher-controlled OpenAI-compatible API. The gateway keeps its URL and credentials private, verifies a synthetic response and benchmarks it.", "model:string endpoint:string apiKey:string", json!({"model":"yg/alice/my-model","endpoint":"https://provider.example/v1","apiKey":"private-key"}), true, None);
    method!(model_registry_upload, "Upload a folder of safe model files as an immutable publication version. resume continues an existing upload ID.", "modelId:string folder:string label:string quant?:string resume?:string", json!({"modelId":"rm-ID","folder":"C:/Models/my-model","label":"v1"}), true, None);
    method!(model_registry_download, "Download an authorized model version to an empty folder and verify every artifact part. Never overwrites unrelated files.", "model:string output:string", json!({"model":"yg/alice/my-model","output":"C:/Models/downloaded"}), true, None);
    method!(model_registry_pause, "Pause the active model artifact transfer, keeping verified progress available for a later retry.", "", json!({}), true, None);
    method!(model_huggingface_status, "Read whether a protected Hugging Face read token is configured. Never returns the token.", "", json!({}), false, None);
    method!(start_environment_download, "Create a complete portable copy of a stopped local environment and publish a temporary download link. Expires when its owning app/CLI exits; counts persist across links. domain reuses a saved Cloudflare domain.", "request:object", json!({"request":{"environmentId":"env-ID","ownerId":"00000000-0000-4000-8000-000000000001","domain":null}}), true, Some("Anyone with the link can download all files and credentials stored inside this environment."));
    method!(list_environment_downloads, "Read active environment-copy links and lifetime completed-download counts.", "", json!({}), false, None);
    method!(keep_environment_downloads_alive, "Renew only this client's temporary download-link leases; cannot revive an expired link.", "ownerId:string", json!({"ownerId":"00000000-0000-4000-8000-000000000001"}), true, None);
    method!(stop_environment_download, "Immediately revoke an environment's download link and cancel active transfers; lifetime count is kept.", "environmentId:string", env.clone(), true, None);
    method!(run_neocloud_model, "Run a Hugging Face model inside an existing RunPod pod over pinned SSH; no resource is created or powered on.", "model:string environmentId:string port?:port", json!({"model":"hf.co/HuggingFaceTB/SmolLM2-135M","environmentId":"env-ID"}), true, None);
    method!(start_model, "Start or reconnect to a saved local or Neocloud model.", "environmentId:string", env.clone(), true, None);
    method!(stop_model, "Stop the model process. A Neocloud pod stays running and billable.", "environmentId:string", env.clone(), true, None);
    method!(test_cloud_connection, "Test SSH credentials and preserve an existing server's pinned identity when editing its connection.", "request:object environmentId?:string",json!({"request":{"name":"Cloud server","vendor":"other","host":"server.example.com","port":22,"username":"ubuntu","identityFile":"C:/Keys/server.pem","hostKey":""}}),true,None);
    method!(duplicate_local_environment, "Copy a stopped local environment and preserve the source.", "environmentId:string name:string storageDrive?:string",json!({"environmentId":"env-ID","name":"Copy"}),true,None);
    method!(duplicate_environment, "Run or resume a reviewed local/cloud copy. Cloud destinations create billable resources; use the same operationId when retrying.", "request:object",json!({"request":{"operationId":"00000000-0000-4000-8000-000000000001","environmentId":"env-ID","name":"Copy","destination":"local","reviewed":false}}),true,Some("May create billable cloud resources and transfer environment data. Review the destination and recovery plan."));
    method!(inspect_duplication_source, "Verify an existing cloud source before copying it.", "environmentId:string source:object",json!({"environmentId":"env-ID","source":{"provider":"aws","account":"profile","region":"eu-west-1","instance":"i-ID"}}),true,None);
    method!(cleanup_environment_duplication, "Remove owned temporary transfer resources belonging to a recorded copy operation.", "operationId:string",json!({"operationId":"00000000-0000-4000-8000-000000000001"}),true,Some("Deletes this copy operation's temporary transfer resources."));
    method!(model_compute_status, "Probe model compute capabilities: CUDA, native Mac Metal or CPU, architecture and memory. Does not download weights.", "",json!({}),false,None);
    method!(run_model, "Run a verified Hugging Face model. resources.backend selects auto, cuda, metal or cpu. macOS uses native GGUF inference with an isolated API frontend; CUDA supports GGUF, Transformers and vLLM. Optional resources: cpu, memoryGb, storageGb, storageDrive. Optional API binds only to localhost and returns a private API key.", "model:string port?:port resources?:object quant?:string folder?:string backend?:string memoryGb?:number",json!({"model":"hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0"}),true,None);
    method!(model_api, "Enable or reconnect a model's authenticated localhost API and reveal its private API key to this user.", "environmentId:string port:port",json!({"environmentId":"env-ID","port":8000}),true,None);
    method!(model_optimizer, "Read or configure automatic GPU memory, idle unloading and pinning.", "environmentId:string enabled?:bool pinned?:bool idleTimeoutSeconds?:number",json!({"environmentId":"env-ID","enabled":true,"idleTimeoutSeconds":120}),true,None);
    method!(model_status, "Read model installation/download/loading/ready status.", "environmentId:string",json!({"environmentId":"env-ID"}),false,None);
    method!(model_chat, "Generate a response in a local GPU model environment. maxTokens defaults to 256 (up to 4096 on models started with this version); temperature defaults to 0.7.", "environmentId:string messages:array maxTokens?:number temperature?:number",json!({"environmentId":"env-ID","messages":[{"role":"user","content":"Hello"}]}),true,None);
    method!(model_chat_begin, "Start a streamed reply in a local GPU model environment and return its requestId; read it with model_chat_read. Parameters as model_chat.", "environmentId:string messages:array maxTokens?:number temperature?:number",json!({"environmentId":"env-ID","messages":[{"role":"user","content":"Hello"}]}),true,None);
    method!(model_chat_read, "Text of a streamed reply produced since offset (a byte offset returned by the previous read). done is true once it ends, with result (finishReason, usage) or error. stop: true asks the model to stop; the text so far is kept.", "requestId:string offset?:integer stop?:bool",json!({"requestId":"poll-ID","offset":0}),false,None);
    method!(model_usage, "Model usage recorded by the model server: requests, tokens in/out, errors and refused API keys per hour, plus recent requests. Never includes prompts.", "environmentId:string", json!({"environmentId":"env-ID"}), false, None);
    method!(reset_model_usage, "Clear a model's recorded usage history.", "environmentId:string", json!({"environmentId":"env-ID"}), true, Some("Permanently clears the usage history."));
    method!(model_chat_history, "A model's saved conversations and chat settings (system prompt, temperature, reply length), shared with the desktop app. Null when nothing is saved.", "environmentId:string", json!({"environmentId":"env-ID"}), false, None);
    method!(save_model_chat_history, "Replace a model's saved conversations and chat settings. Read model_chat_history first and change only what is intended.", "environmentId:string history:object", json!({"environmentId":"env-ID","history":{"conversations":[],"activeId":null,"settings":{"system":"","temperature":0.7,"maxTokens":1024}}}), true, None);
    method!(confidential_network_chat, "Send an encrypted model request only after independently pinned hardware attestation verifies. Supply API credentials through a protected JSON file or stdin, never shell arguments. An empty hardware policy refuses before sending prompts.", "apiKey:string nodeId:string model:string prompt:string policyPath?:string", json!({"apiKey":"YOUR_API_KEY","nodeId":"provider-ID","model":"MODEL_ID","prompt":"Hello"}), true, None);
    method!(market_status, "Yougori Network sign-in, account (email, wallet, balances) and the models this computer shares, with their speed, uptime and token counts. Shared by the app and the CLI.", "", json!({}), false, None);
    method!(market_sign_in, "Start a Yougori Network sign-in: returns a code to approve at yougori.com/device and opens the browser. One approval signs in this computer's app and CLI; read market_status until signedIn.", "", json!({}), true, None);
    method!(market_sign_out, "Sign out of the Yougori Network on this computer and stop sharing every model.", "", json!({}), true, Some("Stops sharing every model this computer shares on the Yougori Network."));
    method!(market_share_model, "Share a running or starting model on the Yougori Network through a private public link that only yougori.com sees. paid lists priced models at the network price (others are shared free); free lets anyone use it without a wallet. Requires market_sign_in.", "environmentId:string mode:paid|free listen?:bool publish?:bool", json!({"environmentId":"env-ID","mode":"free"}), true, Some("Lets other people send requests to this model on your GPU through the Yougori Network."));
    method!(market_unshare_model, "Stop sharing a model on the Yougori Network and close the public link Yougori opened for it.", "environmentId:string", env.clone(), true, None);
    method!(grid_status, "Closed Neo Grid on this computer: as the admin's hub, its computers, plans, models, API keys and queue; as a member, its grid, assignment from the admin's plans and serving state. Never returns secrets.", "", json!({}), false, None);
    method!(grid_suggested_address, "This computer's address on its private LAN or VPN, as suggested for a Closed Neo Grid hub; null when it has none. Nothing is sent to find it.", "", json!({}), false, None);
    method!(grid_create, "Create a company's Closed Neo Grid hub on this computer's private LAN or VPN address (port defaults to 7460) and join it. tunnel also lets computers outside the network join: quick for a temporary trycloudflare.com address that changes when this computer restarts, or a saved domain whose Cloudflare tunnel routes to http://127.0.0.1:HOST_PORT; the tunnel only relays the grid's own pinned TLS. The status's hub.invite is what company computers join with; apps call https://ADDRESS:PORT/v1 on the LAN with keys from grid_key_create. Supply the password through stdin.", "name:string address:string password:string port?:port hostname?:string tunnel?:string", json!({"name":"Acme","address":"10.0.0.5","password":"SUPPLY_ON_STDIN","tunnel":"quick"}), true, Some("Opens a grid service on this computer's network address, and through a tunnel when one is chosen, that computers with the company password can join; the admin's plans then run models on them."));
    method!(grid_password, "Admin: change the company password new computers join with. Joined computers stay members. Supply the password through stdin.", "password:string", json!({"password":"SUPPLY_ON_STDIN"}), true, Some("New computers must use the new password to join."));
    method!(grid_delete, "Admin: delete this computer's grid. when is later (default: paused for three days, nothing serves and no API key works, and grid_restore brings everything back), now (deleted at once), or forget (stop waiting for computers still away and remove the hub right now). Once deleted, each computer is told at its next check-in: it leaves and removes the model environment the grid created. The hub keeps telling computers that come back for up to 30 days, then removes itself.", "when?:string", json!({"when":"later"}), true, Some("Deletes the grid: every computer leaves it, removes the model it installed, and every API key stops working."));
    method!(grid_restore, "Admin: take back a deletion while the grid is still paused (within its three days): computers serve again at their next check-in.", "", json!({}), false, None);
    method!(grid_join, "Join a company's Closed Neo Grid with the invite the admin shared and the company password, which is proven, never sent. The invite names the company, the hub's address (on the LAN or an https:// tunnel) and its certificate fingerprint; without one, give company, address and optionally fingerprint. An invite for the grid this computer is already in only moves it to the hub's current address (a Quick Tunnel gets a new one after a restart) and needs no password. From then on the admin's plans decide which model this computer downloads and runs, in which hours and after how long without keyboard or mouse input. Supply the password through stdin.", "company?:string address?:string password?:string port?:port name?:string fingerprint?:string invite?:string", json!({"invite":"grid-invite:…","password":"SUPPLY_ON_STDIN"}), true, None);
    method!(grid_leave, "Leave the grid: stop serving it, stop the model environment the grid started and forget the membership.", "", json!({}), true, Some("Stops serving the grid; joining again needs the company password."));
    method!(grid_plan_add, "Admin: run a model on percent of the grid's computers that can run models, or on exactly the computers listed in computers (IDs from grid_status), which then leave any model they ran. scope remaining counts only the computers nobody picked; all (default) counts every computer, though picked ones keep their pick. schedule is weekly local hours such as 'Mon-Fri 18:00-08:00; Sat,Sun' (default any time); idleAfter is minutes without keyboard or mouse input before a computer serves (default 10; 0 ignores activity). Assigned computers download, start and serve the model.", "model:string percent?:number schedule?:string idleAfter?:number quant?:string scope?:all|remaining computers?:string[]", json!({"model":"hf.co/Qwen/Qwen3-8B","percent":50,"schedule":"Mon-Fri 18:00-08:00; Sat,Sun","idleAfter":15}), true, None);
    method!(grid_plan_update, "Admin: change a plan's model, share of computers, hours or idle minutes. An empty schedule or quant clears it; a new model makes its computers switch.", "planId:string model?:string percent?:number schedule?:string idleAfter?:number quant?:string", json!({"planId":"plan-ID","percent":75}), true, None);
    method!(grid_plan_remove, "Admin: remove a plan; its computers stop the model environments the grid started.", "planId:string", json!({"planId":"plan-ID"}), true, Some("Stops this model on every computer running the plan."));
    method!(grid_member_remove, "Admin: remove a computer from the grid; it needs the company password to join again.", "memberId:string", json!({"memberId":"member-ID"}), true, Some("Removes this computer from the grid and stops its work for it."));
    method!(grid_member_exclude, "Admin: leave a computer out of the grid's work. It gets no model and no work, so it drops the model the grid gave it (a grid-created model environment is deleted with its weights, a download in progress included). It stays a member; grid_member_include brings it back.", "memberId:string", json!({"memberId":"member-ID"}), true, Some("The computer stops serving and drops the model the grid gave it."));
    method!(grid_member_include, "Admin: bring a computer left out back into the grid's work, so plans and picks may give it a model again.", "memberId:string", json!({"memberId":"member-ID"}), true, None);
    method!(grid_neocloud_status, "Admin: the rented GPUs working in this grid, what each one costs an hour and what it is doing, and the RunPod GPU pods you have rented that are not in the grid yet. hourlyUsd counts only the pods that are running. A grid holds at most 8 rented GPUs.", "", json!({}), false, None);
    method!(grid_neocloud_add, "Admin: put a GPU pod you have already rented in NeoCloud to work in this grid, so its plans may give it a model. It never rents a pod and never starts a stopped one; while the pod runs, RunPod charges its hourly price as usual.", "environmentId:string", json!({"environmentId":"env-ID"}), true, None);
    method!(grid_neocloud_remove, "Admin: take a rented GPU out of this grid and stop its pod, which ends its hourly charge. The pod and its disk stay in NeoCloud; start it there to use it again.", "environmentId:string", json!({"environmentId":"env-ID"}), true, Some("Stops this rented GPU's pod and the work it is doing for the grid."));
    method!(grid_neocloud_stop_all, "Admin: stop every rented GPU in this grid, which ends their hourly charges. They stay in the grid, offline, until you start them in NeoCloud.", "", json!({}), true, Some("Stops every rented GPU in the grid and the work they are doing."));
    method!(grid_swarm_add, "Admin: a swarm harness that company apps call as the model swarm/NAME, so one call runs a team of models on several computers. strategy plan (default): the lead model splits the request into independent tasks with briefs, workers solve them in parallel and the lead combines the results. strategy mixture: the workers each answer the request and the lead writes one answer from all of them. computers caps the requests in flight, so how many computers work on one call; tasks caps tasks per round (plan) or answers per layer (mixture), default computers; rounds is 1-3 rounds (plan) or 1-2 layers (mixture), default 1. lead and workers must run on the grid through plans; missing lists those that do not yet.", "name:string lead:string workers:string[] computers:number strategy?:plan|mixture tasks?:number rounds?:number", json!({"name":"research","lead":"hf.co/Qwen/Qwen3-32B","workers":["hf.co/Qwen/Qwen3-8B"],"computers":5,"strategy":"plan","rounds":2}), true, None);
    method!(grid_swarm_remove, "Admin: remove a swarm harness, by its ID or its name.", "harnessId:string", json!({"harnessId":"research"}), true, Some("Apps calling this swarm model get an error from then on."));
    method!(grid_swarm_run, "Admin: run a swarm harness once on a prompt. Returns the answer and a trace of the plan, which computer did each task, and how long each took.", "harness:string prompt:string", json!({"harness":"research","prompt":"Compare three ways to cut our cloud bill"}), false, None);
    method!(bounty_dispatch, "Import a project folder/file/ZIP, inspect its suggested run recipe, host an isolated private source/web/API bounty on this PC or LAN, connect through a pinned invite and explicitly start a worker on the reviewed snapshot. Public builds reject live URL targets and external-target policies, including joins and resumes. Passwords travel only in a request body or stdin. Actions: inspectProject, hostProject, hostSource, connect, localConnect, discardConnection, startWorker, status.", "request:object", json!({"request":{"action":"status"}}), true, None);
    method!(bounty_status, "Closed Bounty hosted on this computer: the published source, the computers working it (with the model each chose), and the findings they reported. Returns an invite to share. Never returns secrets.", "", json!({}), false, None);
    method!(bounty_suggested_address, "This computer's private LAN or VPN address, suggested as a closed bounty host address; null when it has none. Nothing is sent to find it.", "", json!({}), false, None);
    method!(bounty_host, "Admin: host a Closed Bounty on this computer so other computers can join with the company password and work the source. title names it; instructions and authorization tell workers what to do and what they may test; files is the source as [{path, data}] with data base64 of each file's bytes. The host runs no model. Shares an invite (bounty-invite:...); joiners paste it, enter the password and choose their own model.", "name:string address:string password:string title:string files:array instructions?:string authorization?:string", json!({"name":"Acme","address":"192.168.1.20","password":"SUPPLY_ON_STDIN","title":"Review checkout","files":[{"path":"src/app.py","data":"cHJpbnQoMSk="}]}), true, None);
    method!(bounty_member_remove, "Admin: remove a computer from the closed bounty, by its ID from bounty_status.", "memberId:string", json!({"memberId":"member-ID"}), true, Some("The computer stops working this bounty."));
    method!(bounty_delete, "Admin: stop hosting the closed bounty and delete it from this computer.", "", json!({}), true, Some("Computers working it can no longer reach the host."));
    method!(desks_manage, "Manage Sandbox Grid with named administrator permissions: status, personAdd/personUpdate/personPassword/personRemove, imageAdd/imageImport/imageRemove, roleAdd/roleRemove, deskOrder/deskAssign/deskRetry/deskRemove, computerShare/computerRemove/computerLimit, connectionAdd/connectionCredential/connectionTest/connectionProvision/connectionRevoke/connectionRemove, parkingSet/parkingClear, cloudFallbackSet/cloudFallbackClear, ssoSet/ssoClear, mfaReset. personUpdate also sets a person's email, which the identity provider and the connectors know them by. connectionAdd/connectionCredential take credential {…} with the provider's identifiers and secret (clientSecret or password): the secret goes to the hub computer's vault, never the record; connectionTest signs in with it and says what it reaches; connectionProvision/connectionRevoke {id, personId} assign the person at the provider or take it back (queued; the outcome is in status enterprise.provisioning). The one management core: desks_person_add, desks_add, desks_member_share, desks_member_remove and the rest go through the same rules and audit. personAdd and deskOrder take a workspace roleId or a plain spec {kind,cpu,memoryGb,diskGb,gpu,image} for a desk of that size without a catalog; computerRemove puts the computer's desks back into waiting with their data still on it. Uses the local owner or the signed-in remote administrator. Supply passwords only through JSON stdin. Prepared VM images require HTTPS and SHA-256, or imageImport with a local owner disk path (checksum computed automatically); OCI images require an immutable digest.", "request:object", json!({"request":{"action":"status"}}), true, None);
    method!(desks_status, "Sandbox Grid on this computer: as the admin's hub, its computers (each with its live capacity: cores and cpuUsedPercent, memoryGb and usedMemoryGb, gpu and gpuUsedPercent, freeDiskGb, inUse; and its share: what the grid may take, shareSet false while it is still the suggestion), people and desks, and the invite to share; as a member, the grid it hosts desks for; and this computer's own desk sign-in. Never returns secrets.", "", json!({}), false, None);
    method!(desks_suggested_address, "This computer's address on its private LAN or VPN, as suggested for a Sandbox Grid hub; null when it has none. Nothing is sent to find it.", "", json!({}), false, None);
    method!(desks_create, "Admin: host a Sandbox Grid on this computer's private LAN or VPN address (port 7463), separate from any Closed Neo Grid. Company computers join it with the password and host desks within the share the admin sets for each (desks_member_share), in use or not; this computer joins too. tunnel is quick (a temporary public link, for computers anywhere) or a saved Cloudflare domain; without it the grid is reachable on this network only. Returns the invite (desk-invite:...) to share.", "name:string address:string password:string tunnel?:string", json!({"name":"Acme","address":"192.168.1.20","password":"SUPPLY_ON_STDIN","tunnel":"quick"}), true, None);
    method!(desks_join, "Join a company's Sandbox Grid with the invite (desk-invite:...) the admin shared and the password: this computer then reports what it has and is using, and builds and shares desks within the share the admin sets for it, whether or not someone is using it. name is how the admin sees it (default: the hostname).", "invite:string password:string name?:string", json!({"invite":"desk-invite:...","password":"SUPPLY_ON_STDIN","name":"Design laptop"}), true, Some("This computer hosts sandboxes for the grid's people within the share its admin sets."));
    method!(desks_leave, "Leave the Sandbox Grid: stop sharing the desks on this computer (their sandboxes stay) and forget the membership.", "", json!({}), true, Some("Desks hosted here are placed again elsewhere."));
    method!(desks_delete, "Admin: delete this computer's Sandbox Grid. when is later (default: paused for three days, desks stopped and unshared but kept, nobody signs in, and desks_restore brings everything back), now (deleted at once), or forget (stop waiting for computers still away and remove the hub right now). Once deleted, each computer is told at its next check-in: it leaves and deletes the desks it hosted, with their data; people's desk entries are removed when their app next refreshes. The hub keeps telling computers that come back for up to 30 days, then removes itself.", "when?:string", json!({"when":"later"}), true, Some("Deletes every desk on every computer, with its data, once the grid is gone."));
    method!(desks_adopt_membership, "Take up a Sandbox Grid membership the hub made ahead of time, on a computer the hub created (its cloud fallback): membership is {company, gridId, address, fingerprint, memberId, memberToken, name}, supplied on stdin with --file -. The token stands in for the company password; the hub's certificate is pinned by the fingerprint before anything is sent.", "membership:object", json!({"membership":{"company":"Acme","address":"https://acme.trycloudflare.com","fingerprint":"AB…","memberId":"member-ID","memberToken":"SUPPLY_ON_STDIN","name":"yougori-desk-1"}}), true, Some("This computer joins the sandbox grid and hosts desks."));
    method!(desks_restore, "Admin: take back a deletion while the Sandbox Grid is still paused (within its three days): computers start and share their desks again at their next check-in.", "", json!({}), false, None);
    method!(desks_member_remove, "Admin: remove a computer from the Sandbox Grid; its desks are placed again elsewhere and it needs the password to join again.", "memberId:string", json!({"memberId":"member-ID"}), true, None);
    method!(desks_member_share, "Admin: what the Sandbox Grid may take from a computer for desks, whether or not its person is using it: cpu cores, memoryGb, diskGb, gpu, and idleOnly (take desks only while nobody is using it; default false). Fields left out keep their current values; suggested true goes back to the automatic share (half its cores, half its memory with 2 GB kept back, half its free disk, the GPU if it has one). Desks already on the computer stay. The computer's live use is in desks_status as capacity.", "memberId:string cpu?:number memoryGb?:number diskGb?:number gpu?:bool idleOnly?:bool suggested?:bool", json!({"memberId":"member-ID","cpu":2,"memoryGb":4,"diskGb":50,"gpu":false,"idleOnly":false}), true, None);
    method!(desks_person_add, "Admin: add a person who signs in to open their desk, with a username and password (10-256 characters), and order their desk in the same step: give any of cpu cores, memoryGb, diskGb, gpu or kind (container, microvm, vm) and a desk named after them is ordered with those (defaults: a container of 2 cores, 4 GB, 20 GB, no GPU), placed on the computer with the most room left in its share. With none of them, only the person is added. name is how they are shown; it defaults to the username. Returns the person, with the desk under desk.", "username:string name?:string password:string kind?:string cpu?:number memoryGb?:number diskGb?:number gpu?:bool", json!({"username":"ada.lovelace","name":"Ada Lovelace","password":"SUPPLY_ON_STDIN","cpu":2,"memoryGb":4,"diskGb":20,"gpu":false}), true, Some("Orders a sandbox for the person on a company computer."));
    method!(desks_person_password, "Admin: change a person's password, by their username or ID. Their desks are untouched.", "person:string password:string", json!({"person":"ada.lovelace","password":"SUPPLY_ON_STDIN"}), true, None);
    method!(desks_person_remove, "Admin: remove a person, by their username or ID. Their desks stay, unassigned, with their data.", "person:string", json!({"person":"ada.lovelace"}), true, Some("The person can no longer sign in."));
    method!(desks_add, "Admin: order a desk, a sandbox hosted on a company computer, for a person. kind is container (default), microvm or vm; cpu cores (default 2), memoryGb (default 4), diskGb (default 20), gpu (default false) and image (an OCI image or bootable media; a default per kind) size it. It is built on the computer with the most room left in its share (desks_member_share).", "name:string person?:string kind?:string cpu?:number memoryGb?:number diskGb?:number gpu?:bool image?:string", json!({"name":"Design desk","person":"ada.lovelace","kind":"container","cpu":2,"memoryGb":4,"diskGb":20,"gpu":false,"image":"docker.io/library/ubuntu:24.04"}), true, Some("Builds a sandbox on a company computer and shares it with the person."));
    method!(desks_assign, "Admin: give a desk to a person by username or ID, or to nobody when person is empty. Its data stays.", "desk:string person?:string", json!({"desk":"desk-ID","person":"ada.lovelace"}), true, None);
    method!(desks_retry, "Admin: try a failed desk again on any computer with room in its share.", "desk:string", json!({"desk":"desk-ID"}), true, None);
    method!(desks_remove, "Admin: remove a desk; its computer deletes the sandbox and its data.", "desk:string", json!({"desk":"desk-ID"}), true, Some("Deletes the desk's sandbox and everything in it."));
    method!(desk_refresh, "Refresh assigned desks and enterprise launch connections using the current revocable desk session. Reimports renewed invitations; retires revoked local entries. Does not return credentials.", "", json!({}), true, None);
    method!(desk_login, "Person: sign in to the Sandbox Grid the admin's invite (desk-invite:...) names with your username and password, and open your desks: each ready desk becomes a shared environment in this computer's sandbox list. With two-step sign-in on, code is the six digits from your authenticator app; without it the answer is 'Enter the code from your authenticator app'. With sso true the company's identity provider signs you in instead: the browser opens on it and no username or password is given. Use desk_refresh after a desk moves or its share is renewed; the desktop refreshes automatically.", "invite:string username?:string password?:string code?:string sso?:bool", json!({"invite":"desk-invite:...","username":"ada.lovelace","password":"SUPPLY_ON_STDIN"}), true, None);
    method!(desk_logout, "Person: forget the sign-in and remove the desk entries from this computer. The desks and their data stay on their computers.", "", json!({}), true, Some("Removes your desk entries from this computer."));
    method!(grid_key_create, "Admin: create an API key for a company app. The key is shown once, with the hub's URL and the certificate apps must trust.", "name:string", json!({"name":"Analytics"}), true, None);
    method!(grid_key_revoke, "Admin: revoke a company app's API key immediately.", "keyId:string", json!({"keyId":"key-ID"}), true, Some("Apps using this key stop working immediately."));
    method!(model_api_status, "A model's private API key and any localhost and public (Cloudflare) API addresses currently serving it.", "environmentId:string", json!({"environmentId":"env-ID"}), false, None);
    method!(environment_changes, "Compare explicitly shared PC folders, guest packages, variables and configuration with a saved baseline. baseline:true accepts current changes as a new baseline without editing any source file.", "environmentId:string baseline:bool offset?:number",json!({"environmentId":"env-ID","baseline":false}),true,None);
    method!(inspect_project, "Validate and preview a yougori.yaml; variable values are not returned.", "path:string",json!({"path":"yougori.yaml"}),false,None);
    method!(discover_projects, "Detect project files in the CLI workspace and registered project folders.", "",json!({}),false,None);
    method!(import_compose, "Validate Compose and optionally generate yougori.yaml without overwriting existing files.", "path:string write:bool project?:object",json!({"path":"compose.yaml","write":false}),true,None);
    method!(project_action, "Apply/start or stop a declarative project; preserves removed nodes and persistent data.", "path:string action:up|apply|down",json!({"path":"yougori.yaml","action":"up"}),true,None);
    method!(run_workload, "Create an OCI, GPU, VM or microVM workload and optionally start it.", "request:object start:bool",json!({"request":{},"start":true}),true,None);
    method!(open_isolated_cli,"Create or start the dedicated isolated CLI microVM. It starts with no PC folder access and no environment control grants.","",json!({}),true,None);
    method!(grant_isolated_cli_environment,"Grant the isolated CLI access to only this owned environment. Revocable in sharing controls; expires after 24 hours or engine exit.","environmentId:string permission:view|control",json!({"environmentId":"env-ID","permission":"view"}),true,Some("Grants the isolated CLI the selected guest capabilities."));
    method!(finish_app_close,"Finish a pending desktop close. keepRunning:true hides Yougori windows and keeps the engine, environments and published services running; false stops every running or paused local environment and quits. Quitting refuses while an environment is still being created.","keepRunning:bool",json!({"keepRunning":true}),true,Some("Closes Yougori Desktop, stopping running environments unless they are kept running."));
    method!(delete_cloud_deployment,"Delete a managed cloud VM and its boot disk. Existing networks/security groups and separately attached disks remain. Type its exact provider resource name; inspect an interrupted deletion before retrying.","environmentId:string confirmation:string",json!({"environmentId":"env-ID","confirmation":"provider-resource-name"}),true,Some("Permanently deletes the cloud VM and boot disk."));
    method!(cloud_authenticate, "Authenticate with the official cloud CLI through your browser. account is AWS SSO profile, Azure subscription, or GCP project. Optional sso sets explicit AWS SSO profile fields. Credentials stay with the provider CLI.", "provider:aws|azure|google account:string sso?:object",json!({"provider":"aws","account":"yougori"}),true,None);
    method!(deploy_cloud_environment, "Create a billable AWS/Azure/GCP VM using an existing subnet/security policy. Persist an intent before provisioning. Optional containerImage bootstraps a Podman workload on Ubuntu, mapping guest 8080 to container 80. Configure verified SSH after creating. Set riskAcknowledged:true only after reviewing costs, backups, failure recovery and network access.", "request:object riskAcknowledged:bool",json!({"riskAcknowledged":false,"request":{"provider":"aws","account":"yougori","region":"eu-west-1","name":"website","image":"ami-REQUIRED","machineType":"t3.small","subnet":"subnet-REQUIRED","securityGroup":"sg-REQUIRED","keyPair":"existing-key","username":"ubuntu"}}),true,Some("Creates billable resources. Failures may leave resources charging; keep backups and inspect before retrying."));
    method!(cloud_deployment_action, "Inspect or power a Yougori-managed cloud VM. stop deallocates Azure compute; provider storage and other resources can remain billable. Inspect after an interrupted request before retrying.","environmentId:string action:inspect|start|stop",json!({"environmentId":"env-ID","action":"inspect"}),true,None);
    method!(configure_cloud_environment,"Save explicitly verified SSH access for an existing cloud node or a newly deployed cloud VM.","environmentId:string request:object",json!({"environmentId":"env-ID","request":{"name":"web","vendor":"aws","host":"203.0.113.10","port":22,"username":"ubuntu","identityFile":"C:/Keys/guest.pem","hostKey":"ssh-ed25519 VERIFIED_HOST_PUBLIC_KEY"}}),true,Some("Trusts the server key explicitly verified by the user."));
    method!(get_environment_logs, "Read bounded recent guest workload or VM runtime logs.", "environmentId:string", env.clone(), false, None);
    method!(get_environment_log_window, "Read bounded redacted guest output since an opaque cursor, with rotation and truncation flags. tail and limit are byte counts; limit at most 65536.", "environmentId:string cursor?:string limit?:integer tail?:integer", json!({"environmentId":"env-ID","limit":16384,"tail":16384}), false, None);
    method!(manage_oci_images, "List, pull or remove standard OCI images from Yougori's isolated container engine. Removal never forces deletion of an image in use.", "action:list|pull|remove image?:string", json!({"action":"list"}), true, None);
    method!(create_remote_share, "Create a recipient for one target. Passwords use salted scrypt. Provide request via stdin/file, never shell history. PC sharing is restricted to a confirmed folder; desktop/host command access is unavailable.", "request:object", json!({"request":{"targetId":"env-ID","username":"teammate","password":"replace-with-a-strong-password","permission":"view","expiresAt":null,"folder":"/workspace"}}), true, Some("Grants remote access to the selected target."));
    method!(start_remote_tunnel, "Enable the protected remote gateway through a quick or saved dedicated account tunnel. Reuses a live tunnel; never exposes engine management.", "cloudflare?:object hostPort?:number domain?:string", json!({}), true, Some("Enables public reachability of the authenticated sharing gateway."));
    method!(stop_remote_tunnel, "Stop the tunnel and immediately invalidate all recipient sessions. Workloads remain running.", "", json!({}), true, None);
    method!(list_remote_shares, "List recipients, effective permissions, connection counts, status, links and recent activity. No secrets.", "", json!({}), false, None);
    method!(update_remote_share, "Change permission, reset password, disconnect sessions or revoke a recipient. Every update disconnects affected sessions.", "shareId:string permission?:view|edit|control password?:string revoke:bool", json!({"shareId":"share-ID","revoke":true}), true, None);
    method!(remove_remote_share, "Delete a recipient from the sharing list, ending any of its sessions. Use after revoking or expiry to free the slot.", "shareId:string", json!({"shareId":"share-ID"}), true, Some("Permanently removes this recipient and its invite link."));
    method!(connect_remote_share, "Connect using an HTTPS link and share credentials; persist a remote sidebar entry and save only its session in the OS vault. Send credentials via stdin/file.", "link:string username:string password:string environmentId?:string", json!({"link":"https://example.com/share/share-ID","username":"teammate","password":"provided-by-owner"}), true, None);
    method!(reconnect_remote_share, "Reconnect an existing shared environment using its saved link and credentials. The existing node is updated rather than duplicated.", "environmentId:string", json!({"environmentId":"env-ID"}), true, None);
    method!(download_remote_folder, "Download a remote shared folder into a fresh local subfolder. Existing files are never overwritten; partial downloads are kept on failure.", "environmentId:string path:string destination:string", json!({"environmentId":"env-ID","path":"","destination":"C:/Users/me/Downloads"}), true, None);
    method!(remote_share_request, "Inspect remote permissions, use the desktop, perform permitted file operations, upload files or folders to a managed desk, or log out. Upload uses begin/chunk/finish/cancel; there is no upload read operation. Restricted desks refuse file reads, exec, terminal, power and logs. File paths for ordinary shares are relative to the owner's selected folder.", "environmentId:string method:inspect|files|desktop|logout|upload params:object", json!({"environmentId":"env-ID","method":"files","params":{"operation":"list","path":""}}), true, None);
    method!(create_environment_share, "Share only this environment over pinned TLS on this PC's private LAN/VPN address. view grants summary/logs; control also grants guest commands, terminal and power. Invitation expires after 24 hours or engine exit; copy it securely.", "environmentId:string address:string permission:view|control", json!({"environmentId":"env-ID","address":"192.168.1.20","permission":"view"}), true, Some("Shares this selected environment with anyone receiving its private invitation."));
    method!(list_environment_shares, "List live sharing grants, excluding secret invitations.", "", json!({}), false, None);
    method!(revoke_environment_share, "Revoke a grant, abort its TLS connections and close its terminals. Previously started processes/files remain.", "shareId:string", json!({"shareId":"share-ID"}), true, None);
    method!(import_environment_share, "Trust a private invitation received securely from an environment owner; verify its fingerprint/address out of band. Store the invitation in the OS vault and show only this remote environment.", "invitation:object", json!({"invitation":{"version":1,"address":"192.168.1.20:12345","certificate":"OWNER_CERTIFICATE_PEM","token":"OWNER_INVITATION_TOKEN","expiresAt":2000000000}}), true, Some("Trusts the certificate and invitation received from the owner."));
    method!(get_storage_location, "Actual environment runtime storage folder.", "", json!({}), false, None);
    method!(set_storage_location, "Choose a writable folder on any drive before importing/creating environments, then restart the engine. Existing environments must first be exported and removed; no disk is silently moved or abandoned.", "path:string", json!({"path":"D:/Yougori"}), true, Some("Changes environment storage and restarts Yougori."));
    method!(install_environment_skills, "Generate a concise skill and current access reference inside a running container, microVM or VM. Returns guest paths; full VMs receive an imported-files drive. Never overwrites existing guest files or shares host folders.", "environmentId:string", env.clone(), true, None);
    method!(scan_cloud_host, "Read candidate SSH host keys. Verify the fingerprint with the user/server administrator before trusting one; this does not authenticate or trust the server.", "host:string port:port", json!({"host":"server.example.com","port":22}), false, None);
    method!(add_cloud_environment, "Add an EXISTING Linux SSH server. No provisioning or power changes. Requires OpenSSH locally, Python 3 remotely and a verified host key. Connect/disconnect using set_environment_status running/stopped; never paused or restart.", "request:object", json!({"request":{"name":"Cloud database","vendor":"aws","host":"server.example.com","port":22,"username":"ubuntu","identityFile":"C:/Keys/server.pem","hostKey":"ssh-ed25519 VERIFIED_BASE64_HOST_KEY"}}), true, Some("Adds the existing cloud server and trusts the host key explicitly verified by the user."));
    method!(get_cloud_connection, "Get cloud SSH connection settings and connected private SOCKS/shared-files endpoints. Endpoint loopback addresses are inside the cloud server, not on this PC.", "environmentId:string", env.clone(), false, None);
    method!(get_host_terminal_info, "Inspect host shell, bundled CLI, agent skill setup and this client's host terminal sessions. This is host access, not a guest.", "", json!({}), false, None);
    method!(set_up_agent_access, "Install/update only the unmodified Yougori-managed skill for this user; preserve custom edits.", "", json!({}), true, Some("Installs Yougori agent instructions in this user's shared Yougori workspace."));
    method!(host_terminal_action, "HOST computer terminal, not an isolated guest. request={sessionId:host-UNIQUE,action:create|read|write|resize|close,data?:base64,offset?:integer,cols?:integer,rows?:integer,cwd?:absolutePath}. Host shells refuse administrator elevation.", "request:object", json!({"request":{"sessionId":"host-cli-unique","action":"create","cols":100,"rows":24}}), true, None);
    let policy = json!({"cpu":{"min":0.5,"preferred":2,"max":4,"current":0},"memoryGb":{"min":0.5,"preferred":2,"max":4,"current":0},"priority":"normal","dynamic":true});
    method!(
        get_platform_state,
        "List environments, connections, snapshots, settings and host/provider state.",
        "",
        json!({}),
        false,
        None
    );
    method!(vault_summary, "Personal Vault broker reachability and the number of requests waiting for approval. No item names, clients or values.", "", json!({}), false, None);
    method!(access_status, "Access Grid on this computer: the hub it runs (company, address, port 7465, fingerprint, counts, invite, tunnel) and this person's sign-in with what they may use (credentials, never values), their own requests and, for approvers, auditors and admins, the people, credentials, rules, waiting requests and activity. Never returns values, hashes or keys.", "", json!({}), false, None);
    method!(access_create, "Admin: run an Access Grid on this computer's private LAN or VPN address (port 7465) and sign this computer in as its first admin. It keeps the company's credentials sealed with a key in the OS vault; people's agents use them through it without ever seeing them. tunnel is quick or a saved Cloudflare domain for people outside the network. Supply password on stdin.", "company:string address:string username:string password:string name?:string tunnel?:string", json!({"company":"Acme","address":"192.168.1.20","username":"ada","password":"SUPPLY_ON_STDIN"}), true, Some("Hosting an Access Grid opens a service on this computer's network that keeps the company's credentials."));
    method!(access_delete, "Admin: delete this computer's Access Grid. when later (default) pauses it for three days: nobody signs in or uses its credentials, and access_restore takes it back; then it is deleted. now wipes its credentials, people and rules at once and tells people's computers for 30 days; forget removes it from this computer at once.", "when?:later|now|forget", json!({"when":"later"}), true, Some("The Access Grid stops serving its credentials; with now or forget, they are deleted."));
    method!(access_restore, "Admin: take back a deletion while the Access Grid is still paused (within its three days).", "", json!({}), true, None);
    method!(access_account, "Your own Access Grid account. request.action: twoStepStart (a secret and otpauth link for your authenticator app), twoStepConfirm {code}, twoStepOff {code}, password {password, code?} (other computers must sign in again), signOutOthers, deviceForget {device}. Password on stdin only.", "request:object", json!({"request":{"action":"twoStepStart"}}), true, None);
    method!(access_backup, "Admin, on the hub's computer: write an encrypted backup of the Access Grid (people, credentials, rules, activity log and both keys) to output, sealed with passphrase (on stdin). Restoring it on any computer brings the grid back; people's computers keep trusting it.", "output:string passphrase:string", json!({"output":"D:/backups/acme-access.backup","passphrase":"SUPPLY_ON_STDIN"}), true, None);
    method!(access_restore_backup, "Admin: run an Access Grid on this computer from a backup file, at this computer's LAN or VPN address. People sign in with the new invite; their computers move without a password.", "file:string passphrase:string address:string", json!({"file":"D:/backups/acme-access.backup","passphrase":"SUPPLY_ON_STDIN","address":"192.168.1.20"}), true, Some("This computer runs the Access Grid from the backup, with every credential it holds."));
    method!(access_signin, "Sign in to the company's Access Grid with the admin's invite (access-invite:...): username and password (code is the two-step code when it is on), or sso true to sign in through the company's identity provider in the browser. This computer then stays signed in (30 days after its last use) and your agents use the credentials the rules allow you through yougori access mcp. Supply password on stdin.", "invite:string username?:string password?:string code?:string sso?:bool", json!({"invite":"access-invite:...","username":"ada","password":"SUPPLY_ON_STDIN"}), true, None);
    method!(access_signout, "Sign out of the Access Grid on this computer; its agents can no longer use the company's credentials.", "", json!({}), true, Some("Agents on this computer can no longer use the company's credentials."));
    method!(access_manage, "Manage the Access Grid as its owner or with your permission. request.action: overview, activityExport {limit?}, activityVerify (approvers, auditors, admins); decide {request, approve, hours?, reason?} (approvers and admins; never your own request while someone else can approve); admins: personAdd {username, password, name?, email?, permission member|approver|auditor|admin, teams?}, personUpdate {person, name?, email?, permission?, teams?}, personPassword {person, password}, personTwoStepReset {person}, personSignOut {person}, deviceRevoke {person, device}, personRemove {person}, credentialAdd {name, kind bearer|header|basic|query|oauth|github-app|aws, field?, destinations, value, config?, note?}, credentialUpdate {credential, name?, kind?, field?, destinations?, value?, config?, note?}, credentialRemove {credential}, ruleAdd {credential, who everyone|team:NAME|USERNAME, methods?, path?, decision allow|ask|never, reveal?, limit?, hours?, note?}, ruleRemove {rule}, settingsSet {requireTwoStep}, ssoSet {issuer, clientId, claim?, passwordless?}, ssoClear. config: oauth {tokenUrl, clientId, scope?, audience?, auth basic|body}; github-app {appId, installationId, apiUrl?}; aws {region, service?, roleArn?, externalId?, sessionSeconds?}. Passwords and values on stdin only.", "request:object", json!({"request":{"action":"ruleAdd","credential":"GitHub","who":"team:Research","methods":["GET"],"path":"/repos/acme","decision":"allow"}}), true, None);
    method!(access_use, "Send an HTTP request with a company credential through the Access Grid: the hub adds the credential, sends it to one of the credential's destinations and returns {state, answer:{status, headers, body|bodyBase64, truncated}} with the value hidden. state waiting or running returns an id for access_check.", "credential:string url:string method?:string headers?:object body?:string bodyBase64?:string agent?:string", json!({"credential":"GitHub","method":"GET","url":"https://api.github.com/repos/acme/app"}), true, None);
    method!(access_check, "The state of an Access Grid request by its id: waiting, running, or its answer (handed over once), denial or error.", "id:string", json!({"id":"req-0123456789abcdef"}), true, None);
    method!(access_reveal, "Ask for a company credential to use outside Access Grid, only where a rule allows it; an approver always decides. oauth, github-app and aws credentials hand out a short-lived token or temporary keys, never the credential; others hand out the value, which cannot be recalled. Prefer access_use.", "credential:string reason?:string agent?:string", json!({"credential":"Database","reason":"configure the migration tool"}), true, None);
    // One namespace over the four grids. The noun is the method; the verb is request.do, which
    // is the shape desks_manage, access_manage, swarm_dispatch and bounty_dispatch already use.
    // grid names the grid by the company name its admin typed, its short handle or its id, and
    // may be left out when exactly one grid on this computer can answer. Every word the four
    // products ship keeps working unchanged; this is a second door onto the same handlers.
    // Passwords and credential values arrive only through stdin or a private request file.
    grids_method!(grids_realm, "realm", "The grid itself, whichever of the four it is.", "manage reads the administrator's raw request from a private file. Passwords and passphrases arrive on stdin only. Refused in words when the grid does not do what the verb needs.", json!({"request":{"do":"list"}}));
    grids_method!(grids_people, "people", "The people of a grid: accounts, their passwords, their two-step sign-in and the identity provider.", "Passwords arrive on stdin only. A grid that neither hosts workspaces nor brokers credentials refuses these in words.", json!({"request":{"do":"list"}}));
    grids_method!(grids_computers, "computers", "The computers that belong to a grid, and the computers a person signs in from.", "computer takes the computer's ID, as list shows it. Removing a computer stops what it was running and puts its desks back into waiting.", json!({"request":{"do":"list"}}));
    grids_method!(grids_share, "share", "What an enrolled computer gives the grid.", "computer takes the computer's ID, as yougori grids computers list shows it. drain stops using a computer and bring-back uses it again. A share is what the admin allows, never what the computer has.", json!({"request":{"do":"show"}}));
    grids_method!(grids_models, "models", "Model plans, teams of models, API keys and rented GPUs on a grid that serves models.", "plan and key take IDs, as list shows them; team takes a team's name or ID. gpus lists the GPUs rented in NeoCloud for this grid; gpu takes a rented GPU's environment ID, as gpus shows it. remove-gpu and stop-gpus stop the pods and their hourly charges.", json!({"request":{"do":"list"}}));
    grids_method!(grids_desks, "desks", "Desks: sandboxes built for named people on the company's computers.", "desk takes the desk's ID, as list shows it. Passwords arrive on stdin only.", json!({"request":{"do":"list"}}));
    grids_method!(grids_credentials, "credentials", "Company credentials an agent uses without ever seeing them.", "Values arrive on stdin only.", json!({"request":{"do":"list"}}));
    grids_method!(grids_requests, "requests", "What is waiting for somebody to agree, and the deciding of it.", "Nobody decides their own request while another approver can.", json!({"request":{"do":"list"}}));
    grids_method!(grids_research, "research", "Swarm Mining workers on this computer, read and steered but never started here.", "Starting a worker keeps its own guided setup, yougori start bounty.", json!({"request":{"do":"list"}}));
    grids_method!(grids_connectors, "connectors", "The systems a grid reaches on somebody else's computers, and the accounts it makes there.", "The identifiers go in the record and the secret goes to the hub computer's vault, never the record.", json!({"request":{"do":"list"}}));
    grids_method!(grids_work, "work", "The engine's own journal of what a grids command queued.", "Cancelling is not undoing; inspect what was already done.", json!({"request":{"do":"list"}}));
    method!(grids_rollout, "Moving this computer's four products onto Grid Core, one stage at a time. request.do: status, survey (an inventory of this computer, written to a file and sent nowhere), rehearse (copy every record and run the whole move on the copies), backup {keepForDays?, stage?}, verify {stamp}, restore {product, stamp}, observe (run both paths over the same questions and write down every difference), coverage {profile}, read {product, stamp?}, advance {profile}, back {profile}, retire {profile, keepForDays?}, unretire {stamp}, forget {stamp, force?}. A profile is models, workspaces, research or credentials; a product is neo, sandbox, swarm or access. Nothing here reaches a network, nothing is uploaded, and forget is the only verb that deletes anything and refuses until the retention has run out.", "request:object", json!({"request":{"do":"status"}}), true, None);
    grids_method!(grids_log, "log", "What a grid recorded, and whether the record is whole.", "command is one typed command's name, such as keen-heron-3f1a, and finds everything that command caused. Exporting the record is the Access Grid's own door; other grids keep their history in the engine's audit log.", json!({"request":{"do":"show"}}));
    method!(open_personal_vault, "Bring the Yougori dashboard forward on Personal Vault (home, approvals or add). The person decides there; approvals and item entry never happen from the CLI.", "view?:home|approvals|add", json!({"view":"approvals"}), false, None);
    method!(
        get_connection_skills,
        "Live agent instructions for the node's saved connections and My PC shares.",
        "environmentId:string",
        env.clone(),
        false,
        None
    );
    method!(create_environment, "Create Container, GPU (container/yougoriCuda), VM (fullVm), or microVM (microVm). GPU needs compatible hardware/runtime. VM creation waits for disk preparation, not OS installation.", "request:object", json!({"request":{"name":"web","kind":"container","provider":"yougoriOci","runtime":"docker.io/library/node:24","description":"","networkAccess":true,"gpuAccess":false,"resourcePolicy":policy.clone()}}), true, None);
    method!(
        set_environment_status,
        "Start, stop or pause using the same recovery and lifecycle checks as the desktop.",
        "environmentId:string status:running|stopped|paused",
        json!({"environmentId":"env-ID","status":"running"}),
        true,
        None
    );
    method!(restart_environment, "Stop and start this environment using normal runtime checks. This is a runtime restart, not guest OS installation progress.", "environmentId:string", env.clone(), true, None);
    method!(recover_environment_runtime, "Choose the correct abandoned-runtime recovery for the node's saved provider; never format its disk.", "environmentId:string confirmed:bool", json!({"environmentId":"env-ID","confirmed":true}), true, Some("Stops/recover the affected runtime, which may serve multiple containers."));
    method!(delete_environment, "Delete this environment and its managed data; source images/backups follow the desktop's retention rules.", "environmentId:string recoverRuntime?:bool", env.clone(), true, Some("Permanently deletes this environment's data."));
    method!(security_monitor, "Security monitoring per environment: blocked attempts to reach PC ports, the metadata address or the Internet while it is off; new outbound connections per minute; data sent in the last hour; CPU/memory against the allocation; active alerts, kill-switch containment, measurement coverage and the policies in force.", "environmentId?:string", json!({}), false, None);
    method!(security_audit, "Read the engine's tamper-evident audit log, oldest first: lifecycle, exec and terminal sessions (program name, length and salted hash only), file copies, credential imports, sharing and revocations, port publications, Internet/GPU changes, blocked network attempts, alerts and kill-switch actions. since accepts RFC 3339, YYYY-MM-DD (UTC) or 90s/30m/2h/7d; limit 1-1000 (default 50); verify checks every hash link, rotation and the head anchor.", "environmentId?:string since?:string limit?:integer verify?:bool", json!({"environmentId":"env-ID","since":"2h","limit":50,"verify":true}), false, None);
    method!(security_lockdown, "Kill switch: cut Internet access and pause the environment (stopped ones stay offline and cannot start); all:true covers every local container, GPU container, microVM and VM. Containment persists across restarts until security_unlock; starting, Internet, port publishing, PC folders and remote/LAN/download sharing are refused meanwhile. Never stops or deletes anything. Repeating it is harmless.", "environmentId?:string all?:bool", json!({"environmentId":"env-ID"}), true, Some("Cuts Internet access and pauses the selected environments until unlock."));
    method!(security_unlock, "Undo a lockdown or automatic kill switch: restore exactly what containment changed (Internet, then resume) and pause automatic kill switches for that environment for 30 minutes. all:true releases every contained environment. Repeating it is harmless.", "environmentId?:string all?:bool", json!({"environmentId":"env-ID"}), true, Some("Restores Internet access and resumes environments that a lockdown or kill switch contained."));
    method!(
        factory_reset_environment,
        "Erase guest data, retain source image. confirmation must be the exact environment name.",
        "environmentId:string confirmation:string",
        json!({"environmentId":"env-ID","confirmation":"EXACT_NAME"}),
        true,
        Some("Erases guest data. Back up anything needed first.")
    );
    method!(
        recover_container_runtime,
        "Recover only this Yougori runtime when no other live owner exists.",
        "environmentId:string confirmed:bool",
        json!({"environmentId":"env-ID","confirmed":true}),
        true,
        Some("Stops the affected runtime; may affect its other environments.")
    );
    method!(
        recover_vm_runtime,
        "Recover a failed VM runtime without formatting its disk.",
        "environmentId:string confirmed:bool",
        json!({"environmentId":"env-ID","confirmed":true}),
        true,
        Some("Stops/recover the affected VM runtime.")
    );
    method!(
        rename_environment,
        "Change only the environment's display name; keeps runtime IDs, disks and connections unchanged.",
        "environmentId:string name:string",
        json!({"environmentId":"env-ID","name":"Work VM"}),
        true,
        None
    );
    method!(update_container_startup_command, "Change a stopped local container's startup command while preserving its files and data volumes. Runs on next start; empty command restores the original image default. Includes CUDA containers.", "environmentId:string command:string", json!({"environmentId":"env-ID","command":"cd /project && exec npm start"}), true, None);
    method!(
        update_resource_policy,
        "Set CPU cores and memory GB min/preferred/max. Dynamic allocation remains enabled.",
        "environmentId:string resourcePolicy:object",
        json!({"environmentId":"env-ID","resourcePolicy":policy}),
        true,
        None
    );
    method!(configure_resource_limits, "Change only the supplied CPU/memory ranges or priority; preserve the other saved limits. CPU cores, memory GB. Each range accepts min/preferred/max.", "environmentId:string cpu?:object memoryGb?:object priority?:low|normal|high|critical", json!({"environmentId":"env-ID","memoryGb":{"preferred":4,"max":8}}), true, None);
    method!(reclaim_storage, "Return unused container disk blocks to the host; compact only idle runtime storage. Keeps containers, snapshots, cached container images and exported backups. Reports deferred cleanup and measured disk reduction.", "", json!({}), true, Some("Reclaim unused storage; no running workloads are stopped."));
    method!(
        get_storage_allocation,
        "Inspect this node's storage capacity, usage and available maximum. Containers also report whether their independent writable limit is enforced.",
        "environmentId?:string newVm?:bool storageDrive?:string",
        env.clone(),
        false,
        None
    );
    method!(
        expand_environment_storage,
        "Adjust this container's storage limit from 1 GB to available capacity, above current usage. Enabled limits increase or decrease online; legacy containers must stop once. VM disks only grow and require stopping the VM.",
        "environmentId:string capacityGb:number",
        json!({"environmentId":"env-ID","capacityGb":100}),
        true,
        None
    );
    method!(
        update_container_network,
        "Toggle Internet immediately for running or paused containers, microVMs and VMs without restarting. Private connections are separate.",
        "environmentId:string enabled:bool",
        json!({"environmentId":"env-ID","enabled":true}),
        true,
        None
    );
    method!(
        update_environment_gpu,
        "Change existing GPU access, subject to provider support and stopped-state requirements.",
        "environmentId:string enabled:bool",
        json!({"environmentId":"env-ID","enabled":true}),
        true,
        None
    );
    method!(create_connection, "Grant private node-to-node permissions across providers. Files is a designated folder, not a peer's entire disk.", "request:object", json!({"request":{"sourceId":"env-A","targetId":"env-B","direction":"bidirectional","permissions":["files","ports"],"ports":["5432"]}}), true, None);
    method!(
        set_connection_active,
        "Enable/disable a saved node connection.",
        "connectionId:string active:bool",
        json!({"connectionId":"conn-ID","active":false}),
        true,
        None
    );
    method!(
        delete_connection,
        "Remove a node connection and revoke access; retained shared data is not erased.",
        "connectionId:string",
        json!({"connectionId":"conn-ID"}),
        true,
        None
    );
    method!(attach_host_folder, "Share one explicitly chosen host folder. Inspect returned readOnly and mountPath/guestUrl for actual access.", "environmentId:string path:string readOnly:bool", json!({"environmentId":"env-ID","path":"C:/Projects/site","readOnly":true}), true, Some("Grants the environment access to this host folder."));
    method!(copy_files_to_environment, "Copy selected absolute host paths into a running local environment or connected SSH cloud server. Originals are only read. Full VMs receive an independent imported-files drive; other guests receive a unique directory. No live host share or automatic execution. Optional destination (containers and microVMs) chooses the guest folder, for example a mounted named volume; a new yougori-import subfolder is still created there.", "environmentId:string paths:string[] destination?:string", json!({"environmentId":"env-ID","paths":["C:/Projects/site"]}), true, Some("Copies only the selected host files into this environment; originals stay unchanged."));
    method!(copy_files_from_environment, "Copy a file or folder out of a running container, microVM, connected cloud server or environment shared with you into a new folder on this PC (DEST/NAME, or NAME (2) … so nothing is overwritten). Symlinks and special files are skipped. Full VMs are not supported; use their own SSH.", "environmentId:string path:string destination:string", json!({"environmentId":"env-ID","path":"/app/data","destination":"C:/Users/me/Downloads"}), true, None);
    method!(copy_files_between_environments, "Copy one file or folder from a running source environment into a different running destination. A temporary host staging folder is removed when the transfer finishes; existing destination files are not overwritten.", "sourceId:string targetId:string path:string", json!({"sourceId":"env-source","targetId":"env-target","path":"/app/data"}), true, None);
    method!(neocloud_providers, "List supported managed cloud providers and explain which integrations are available.", "", json!({}), false, None);
    method!(runpod_status, "Check RunPod tools and account readiness.", "", json!({}), false, None);
    method!(runpod_connect, "Install RunPod tools if needed and optionally verify and save an API key. Supply secrets through stdin.", "apiKey?:string", json!({}), true, Some("Installs RunPod tools and saves supplied credentials."));
    method!(runpod_catalog, "Read current RunPod GPU prices, stock and templates.", "", json!({}), false, None);
    method!(runpod_disconnect, "Forget the saved RunPod account key; existing resources keep running.", "", json!({}), true, Some("Removes Yougori's saved RunPod credentials."));
    method!(runpod_template, "Read a RunPod template and its configuration.", "id:string", json!({"id":"template-id"}), false, None);
    method!(runpod_search_templates, "Search RunPod templates.", "term:string", json!({"term":"pytorch"}), false, None);
    method!(runpod_hub, "Browse RunPod serverless Hub repositories.", "search?:string", json!({"search":"language"}), false, None);
    method!(runpod_hub_repo, "Read one serverless Hub repository.", "id:string", json!({"id":"repo-id"}), false, None);
    method!(runpod_links, "Read service links for a managed RunPod environment. Links may include a private service token: do not publish them.", "environmentId:string", json!({"environmentId":"env-ID"}), false, None);
    method!(runpod_logs, "Read logs for a managed RunPod environment.", "environmentId:string", json!({"environmentId":"env-ID"}), false, None);
    method!(runpod_create_endpoint, "Create a serverless endpoint from a reviewed Hub repository.", "request:object", json!({"request":{"name":"model-api","hubId":"repo-id","workersMin":0,"workersMax":1}}), true, Some("Creates a billable serverless endpoint. Always-on workers and storage may incur ongoing charges."));
    method!(runpod_endpoint_run, "Send one JSON request to a managed serverless endpoint and wait for its result.", "environmentId:string input:object", json!({"environmentId":"env-ID","input":{"prompt":"Hello"}}), true, Some("Runs inference on your provider account and may incur charges."));
    method!(runpod_action, "Refresh, start, stop, restart or delete a managed RunPod resource. Deletion also requires its exact name in confirmation.", "environmentId:string action:refresh|start|stop|restart|delete confirmation?:string", json!({"environmentId":"env-ID","action":"refresh"}), true, None);
    method!(runpod_resources, "List existing pods, endpoints, volumes and registry logins in your account.", "", json!({}), false, None);
    method!(runpod_attach, "Add an existing pod or endpoint to Yougori. Pods receive Yougori's SSH public key for subsequent starts.", "kind:pod|endpoint resourceId:string", json!({"kind":"pod","resourceId":"pod-id"}), true, Some("Adds this resource to Yougori and may add its SSH public key to the provider account."));
    method!(runpod_volume, "Create, grow or permanently delete a network volume.", "action:create|resize|delete id?:string name?:string location?:string sizeGb?:number", json!({"action":"create","name":"model-data","location":"US-KS-2","sizeGb":50}), true, Some("Changes billable network storage. Deleting a volume permanently erases its data."));
    method!(runpod_registry, "Save or remove a private registry login. Supply passwords through --file -.", "action:create|delete id?:string name?:string username?:string password?:string", json!({"action":"create","name":"registry","username":"account","password":"SUPPLY_ON_STDIN"}), true, Some("Stores or removes registry credentials in the provider account."));
    method!(runpod_gpu_offers, "Check GPU stock separately for Secure and Community Cloud, for 1–8 GPUs (default 1) with public SSH and the chosen disk size.", "containerDiskGb?:number gpuCount?:number", json!({"containerDiskGb":40,"gpuCount":1}), false, None);
    method!(runpod_create_pod, "Create a RunPod pod at the reviewed price and configure SSH access.", "request:object", json!({"request":{"name":"model","compute":"gpu","gpuId":"NVIDIA RTX A4000","containerDiskGb":40,"image":"runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404","maxHourlyUsd":0.5}}), true, Some("Creates a billable RunPod pod. Storage charges may continue while stopped."));
    method!(neocloud_install, "Install one official provider CLI into this user's Yougori data folder and verify it.", "provider:string", json!({"provider":"runpod"}), true, Some("Downloads and installs the selected provider CLI on this computer."));
    method!(neocloud_account, "Check the provider CLI installation and authenticated account without creating resources.", "provider:string location?:string", json!({"provider":"runpod"}), false, None);
    method!(neocloud_catalog, "List CPU or GPU hardware, prices, stock, images and provider resource choices. Partial failures remain visible alongside successful lookups.", "provider:string product:cpu|gpu location?:string", json!({"provider":"jarvis","product":"cpu"}), false, None);
    method!(neocloud_authenticate, "Verify and save an API key in the system credential store. Supply secrets through --file -; never through shell arguments.", "provider:string apiKey:string location?:string", json!({"provider":"runpod","apiKey":"SUPPLY_ON_STDIN"}), true, Some("Stores a provider API key in the system credential store."));
    method!(neocloud_forget_account, "Remove the API key saved by Yougori. Existing credentials in the provider CLI remain under that CLI's control.", "provider:string", json!({"provider":"runpod"}), true, Some("Removes Yougori's saved provider API key."));
    method!(neocloud_discover, "Discover current provider offerings using its installed CLI and configured account.", "provider:string location?:string", json!({"provider":"runpod","location":"US"}), false, None);
    method!(neocloud_prices, "Compare fresh CPU or GPU offers across supported, authenticated provider CLIs. Rank only explicit USD hourly compute prices; report unavailable, unpriced and unsupported providers separately. offer selects one exact provider offer ID. --hours estimates compute only, not total charges. location supplies a Civo region or Nebius project, not a universal geographic filter.", "provider?:string product?:gpu|cpu offer?:string location?:string hours?:number maxHourly?:number minVramGb?:number limit?:number", json!({"product":"gpu","hours":8}), false, None);
    method!(neocloud_plan, "Validate one provider resource request without contacting its account or creating anything. Return a local-first trial workflow, distinguishing OCI images from provider VM/template/model IDs, plus compute access constraints and a quote command. Pass {request:{provider,product,name,image,offer,location,diskGb,...}} via --file; actual price and account readiness still need separate checks.", "request:object", json!({"request":{"provider":"vast","product":"gpu","name":"model","image":"pytorch/pytorch:latest","offer":"123","location":"","diskGb":20}}), false, None);
    method!(create_neocloud_environment, "Create a provider resource after reviewing its account, price and charges. Requires explicit cost acknowledgment; stopping may not stop every provider charge.", "request:object costAcknowledged:bool", json!({"request":{"provider":"runpod","product":"gpu","name":"model","image":"runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404","offer":"NVIDIA H100 80GB HBM3","location":"US-KS-2","diskGb":40,"maxHourlyUsd":2.69},"costAcknowledged":true}), true, Some("Creates a billable resource in the configured provider account."));
    method!(neocloud_action, "Inspect, start, stop or delete a managed provider resource. Stop may leave storage or instance charges; inspect the provider details before acting.", "environmentId:string action:inspect|start|stop|delete confirmation?:string", json!({"environmentId":"env-ID","action":"inspect"}), true, None);
    method!(neocloud_recover_id, "Attach a verified provider resource ID to a pending Yougori node after an ambiguous creation response.", "environmentId:string resourceId:string", json!({"environmentId":"env-ID","resourceId":"provider-resource-id"}), true, None);
    method!(list_volumes, "Named volumes: every environment that mounts them (guest path, read-only, running) and what each container runtime stores, including volumes left by deleted environments (inUse false). Only running runtimes are checked unless scan is true, which starts stopped ones. size adds up each volume's files. Volumes are created when an environment first mounts one.", "scan?:bool size?:bool", json!({"scan":false,"size":false}), false, None);
    method!(cloud_options, "Read-only lookups for deploy_cloud_environment through the signed-in provider CLI: kind regions|images|machineTypes|subnets|securityGroups|keyPairs (AWS)|resourceGroups (Azure)|sshKeys (local ~/.ssh public keys). machineTypes needs region; Google subnets need the zone as region. Returns items [{id,name,detail}] where id is the value for the request field named by field. Nothing is created.", "provider:aws|azure|google account:string region?:string kind:string", json!({"provider":"aws","account":"yougori","region":"eu-west-1","kind":"subnets"}), false, None);
    method!(remove_volume, "Permanently delete a named volume and its data from every container runtime that keeps it (starting stopped runtimes to look; the GPU runtime only while it runs). Refused while any environment mounts it.", "name:string", json!({"name":"old-data"}), true, Some("Permanently deletes the volume and every file in it."));
    method!(list_imported_drives, "List a full VM's connected and saved imported-files drives.", "environmentId:string", env.clone(), false, None);
    method!(set_imported_drive_attached, "Connect or disconnect an imported-files drive while its VM is shut down. Disconnected images and guest edits remain saved.", "environmentId:string transferId:string attached:bool", json!({"environmentId":"env-ID","transferId":"0123456789abcdef0123456789abcdef","attached":false}), true, None);
    method!(
        detach_host_folder,
        "Revoke one My PC folder share.",
        "shareId:string",
        json!({"shareId":"share-ID"}),
        true,
        None
    );
    method!(
        list_environment_services,
        "Discover guest TCP services and list live publications and My PC shares.",
        "environmentId:string",
        env.clone(),
        false,
        None
    );
    method!(
        get_manual_service_ports,
        "List persisted graph service-port declarations, including stopped nodes.",
        "",
        json!({}),
        false,
        None
    );
    method!(set_manual_service_port, "Add/remove a port on the graph. This does not start a service, publish a port, or grant access.", "environmentId:string port:port present:bool", json!({"environmentId":"env-ID","port":3000,"present":true}), true, None);
    method!(publish_environment_service, "Publish a TCP service to local LAN or Cloudflare HTTPS. Optional account credentials: cloudflare={hostname,token?,remember,routesReviewed}, plus fixed hostPort. No credentials means Quick Tunnel. domain names a saved domain (see list_saved_domains) and reuses its vaulted token instead of kind/hostPort/cloudflare.", "environmentId:string port:port kind?:local|cloudflare|loopback hostPort?:port cloudflare?:object domain?:string", json!({"environmentId":"env-ID","port":3000,"kind":"cloudflare"}), true, Some("Exposes a guest service outside its private node network. Cloudflare URLs are public."));
    method!(list_saved_domains, "List saved domains (reusable Cloudflare account tunnels) shared with the desktop app. Tokens are never returned.", "", json!({}), false, None);
    method!(start_saved_domain_tunnel, "Connect a saved domain's tunnel so its connector appears in Cloudflare before an environment is attached. Waits for registration. The local port serves a setup placeholder until an environment is connected. Reuses an existing connector or matching publication.", "domain:string", json!({"domain":"app.example.com"}), true, Some("Starts a Cloudflare connector using its vaulted token. Review the dedicated tunnel's routes in Cloudflare."));
    method!(stop_saved_domain_tunnel, "Stop a saved domain's setup connector. Active environment publications are unaffected.", "domain:string", json!({"domain":"app.example.com"}), true, Some("Disconnects the setup connector from Cloudflare."));
    method!(add_saved_domain, "Save a Cloudflare account tunnel for reuse. Configure the tunnel's public hostname route to http://127.0.0.1:hostPort first. The token goes to the OS vault; pass it via stdin/file, never shell history. port is the app port it is labelled for (defaults to hostPort).", "hostname:string hostPort:port port?:port token:string", json!({"hostname":"app.example.com","hostPort":45000,"token":"TUNNEL_TOKEN"}), true, Some("Stores a tunnel token in the OS credential vault."));
    method!(remember_saved_domain, "Copy this environment's already-saved Cloudflare tunnel into reusable Saved setups without revealing its token. The tunnel must have been connected with Remember for this node and port.", "environmentId:string port:port", json!({"environmentId":"env-ID","port":3000}), true, Some("Makes this node's saved tunnel available for use by other environments."));
    method!(update_saved_domain, "Change a saved domain's app port and/or local tunnel port (by hostname or ID). The vaulted token moves with it; node connections saved for this domain follow the new tunnel port. Disconnect any environment using the domain before changing its tunnel port, then update the tunnel's Cloudflare route to http://127.0.0.1:hostPort.", "domain:string port?:port hostPort?:port", json!({"domain":"app.example.com","hostPort":45001}), true, Some("Changes the saved tunnel's ports; its Cloudflare route must match the new tunnel port."));
    method!(remove_saved_domain, "Remove a saved domain by hostname or ID and forget its vaulted token. Active publications keep running until unpublished.", "domain:string", json!({"domain":"app.example.com"}), true, Some("Forgets the saved tunnel token."));
    method!(
        unpublish_environment_service,
        "Close a service publication/tunnel.",
        "publicationId:string",
        json!({"publicationId":"pub-ID"}),
        true,
        None
    );
    method!(
        saved_cloudflare_account,
        "Inspect saved hostname/port; never returns the stored token.",
        "environmentId:string port:port",
        json!({"environmentId":"env-ID","port":3000}),
        false,
        None
    );
    method!(
        forget_cloudflare_account,
        "Remove saved Cloudflare credentials for this service from the OS vault.",
        "environmentId:string port:port",
        json!({"environmentId":"env-ID","port":3000}),
        true,
        Some("Removes the saved tunnel credential, not the Cloudflare account.")
    );
    method!(
        create_snapshot,
        "Create a local environment snapshot.",
        "environmentId:string name:string",
        json!({"environmentId":"env-ID","name":"before-change"}),
        true,
        None
    );
    method!(
        delete_snapshot,
        "Delete a saved snapshot.",
        "snapshotId:string",
        json!({"snapshotId":"snap-ID"}),
        true,
        Some("Permanently deletes this snapshot.")
    );
    method!(
        restore_snapshot,
        "Restore a snapshot, replacing the environment's current state.",
        "snapshotId:string",
        json!({"snapshotId":"snap-ID"}),
        true,
        Some("Replaces current guest data with the snapshot.")
    );
    method!(
        export_local_backup,
        "Save a local backup into an existing host folder.",
        "environmentId:string folder:string",
        json!({"environmentId":"env-ID","folder":"C:/Backups"}),
        true,
        None
    );
    method!(import_local_backup, "Import a backup as a new environment. Optional targetProvider supports explicit CUDA migration. Restored external permissions remain revoked.", "path:string targetProvider?:yougoriOci|yougoriCuda|qemu", json!({"path":"C:/Backups/example.yougori-backup"}), true, None);
    method!(add_backup_destination, "Add/verify a cloud backup destination. Supply credentials via stdin/private JSON file, not command arguments.", "request:object", json!({"request":{"name":"backup","provider":"awsS3","location":"s3://bucket/prefix","accessKey":"REDACTED","secretKey":"REDACTED"}}), true, Some("Stores credentials in the OS vault and contacts this backup provider."));
    method!(
        delete_backup_destination,
        "Remove a saved backup destination.",
        "destinationId:string",
        json!({"destinationId":"dest-ID"}),
        true,
        Some("Removes this destination and its local backup history.")
    );
    method!(
        run_backup,
        "Create/encrypt/upload a backup to a saved destination.",
        "environmentId:string destinationId:string",
        json!({"environmentId":"env-ID","destinationId":"dest-ID"}),
        true,
        Some("Uploads environment data to the selected destination.")
    );
    method!(
        restore_backup,
        "Restore a completed cloud backup.",
        "backupId:string",
        json!({"backupId":"backup-ID"}),
        true,
        Some("Restores backup data over the existing environment.")
    );
    method!(update_settings, "Save the complete settings object from get_platform_state, modifying only intended fields. Pass expectedRevision (settingsRevision from the same read) to refuse the write if settings changed since; patch_settings is preferred.", "settings:object expectedRevision?:integer", json!({"settings":{"theme":"system","launchAtStartup":false,"minimizeToTray":false,"pauseOnBattery":false,"telemetryEnabled":false,"dataDirectory":"","snapshotRetention":20,"bandwidthLimitMbps":0}}), true, None);
    method!(
        refresh_host_metrics,
        "Refresh host usage and enforce dynamic resource limits.",
        "",
        json!({}),
        false,
        None
    );
    method!(
        reset_platform_state,
        "Reset all managed platform state using the desktop's safety checks.",
        "",
        json!({}),
        true,
        Some("Resets the whole platform; do not use for an individual node.")
    );
    method!(
        get_cuda_runtime_status,
        "Read actual NVIDIA/WSL compatibility and installation checks.",
        "storageDrive?:string",
        json!({}),
        false,
        None
    );
    method!(
        install_cuda_runtime,
        "Install/update Yougori's dedicated CUDA runtime, not the user's other WSL distributions.",
        "storageDrive?:string",
        json!({}),
        true,
        Some("Installs/updates the dedicated WSL CUDA runtime.")
    );
    method!(
        verify_environment_cuda,
        "Execute a small real CUDA kernel inside this GPU container.",
        "environmentId:string",
        env.clone(),
        false,
        None
    );
    method!(
        get_shared_gpu_settings,
        "Inspect legacy QEMU graphics adapter settings; this is not CUDA passthrough.",
        "",
        json!({}),
        false,
        None
    );
    method!(set_shared_gpu_selection, "Change the legacy graphics adapter selection with the same stopped-runtime checks as the desktop.", "selectedId?:string", json!({"selectedId":null}), true, None);
    method!(execute_environment_command, "Execute a guest shell command: files, code, processes and applications. Full VMs require request.ssh={username,identityFile,hostKey,port?:22}; hostKey must be verified in the guest. Uses a temporary loopback forward with pinned SSH, 120s timeout and 256KiB per output stream. Containers/microVMs use their agent; cloud servers use their authenticated SSH session.", "request:object", json!({"request":{"environmentId":"env-ID","command":"uname -a"}}), true, Some("Runs the supplied command inside the guest; an optional SSH identity path explicitly authorizes using that selected host key file."));
    method!(execute_connected_command, "Run a bounded command in the directly connected peer only when Commands is granted and both endpoints are ready. Full VMs require request.ssh with verified host key and guest identity. Never traverses a second connection.", "request:object", json!({"request":{"connectionId":"conn-ID","sourceId":"env-ID","command":"ls"}}), true, Some("Executes as the target guest account. A delete or other destructive command changes the target immediately."));
    method!(list_environment_folders, "Browse folder and file names inside a running container, managed microVM, cloud node or the owner's already shared folder. An empty path starts in the guest's working or project folder. Does not expose file content.", "environmentId:string path:string", json!({"environmentId":"env-ID","path":""}), false, None);
    method!(request_connected_files, "Browse or edit files on an active private connection from its named environment. Use path _selected/N for a selected guest folder. Read and write permissions are enforced by the connection; this does not expose the host filesystem.", "environmentId:string request:object", json!({"environmentId":"env-ID","request":{"connectionId":"conn-ID","operation":"list","path":"_selected/0"}}), true, Some("Writes and deletes affect the connected guest's original files immediately."));
    method!(
        read_environment_console,
        "Read the guest serial console.",
        "environmentId:string",
        env.clone(),
        false,
        None
    );
    method!(get_guest_session, "Get console connection details. Output may include a private console credential: do not publish it.", "environmentId:string", env.clone(), false, None);
    method!(terminal_action, "Create/read/write/resize/close CLI-owned terminal sessions. data is base64; use returned offset when reading.", "environmentId:string sessionId:string action:create|read|write|resize|close data?:string offset?:integer cols?:integer rows?:integer", json!({"environmentId":"env-ID","sessionId":"term-cli-unique","action":"create","cols":100,"rows":30}), true, None);
    method!(prepare_terminal_installer, "Stage a supported tool in a CLI-owned terminal; returns its short launcher command, without executing it.", "environmentId:string sessionId:string tool:codex|claude|gemini|ollama|opencode|kilo|openclaw", json!({"environmentId":"env-ID","sessionId":"term-cli-unique","tool":"ollama"}), true, Some("Stages a coding-tool installer inside this container."));
    method!(install_terminal_tool, "Stage and immediately start the supported tool installer in a CLI-owned terminal. Read terminal output for progress/result.", "environmentId:string sessionId:string tool:codex|claude|gemini|ollama|opencode|kilo|openclaw", json!({"environmentId":"env-ID","sessionId":"term-cli-unique","tool":"ollama"}), true, Some("Downloads/installs this tool inside the container."));
    method!(micro_vm_apps, "Manage built-in microVM guest app sessions. The runtime validates action/package/command.", "environmentId:string action:status|install|launch|stop|view sessionId?:string name?:string command?:string package?:string", json!({"environmentId":"env-ID","action":"status"}), true, None);
    method!(
        open_environment_window,
        "Open another graphical guest window (not an extra physical/virtual monitor).",
        "environmentId:string",
        env.clone(),
        true,
        None
    );
    method!(
        open_micro_vm_app_window,
        "Open a built-in microVM application session window.",
        "environmentId:string sessionId:string",
        json!({"environmentId":"env-ID","sessionId":"app-ID"}),
        true,
        None
    );
    method!(
        close_environment_window,
        "Close the specified guest window without stopping its environment.",
        "label:string",
        json!({"label":"environment-env-ID-WINDOW"}),
        true,
        None
    );
    method!(
        list_environment_windows,
        "List currently open guest windows.",
        "",
        json!({}),
        false,
        None
    );
    method!(
        focus_environment_window,
        "Focus a guest window.",
        "label:string",
        json!({"label":"environment-env-ID-WINDOW"}),
        true,
        None
    );
    method!(
        title_environment_window,
        "Refresh a specified guest window's title from its environment.",
        "environmentId:string label:string",
        json!({"environmentId":"env-ID","label":"environment-env-ID-WINDOW"}),
        true,
        None
    );
    method!(set_guest_keyboard_capture, "Set/release guest keyboard capture for a specific window using the existing capture token and viewport bounds.", "label:string token:string bounds?:object", json!({"label":"environment-env-ID-WINDOW","token":"TOKEN","bounds":null}), true, None);
    method!(
        open_workspace_url,
        "Open an HTTP(S) URL in the host browser.",
        "url:string",
        json!({"url":"http://127.0.0.1:13000"}),
        true,
        None
    );
    method!(
        open_service_window,
        "Open one of this environment's own web services in a Yougori browser window. Only loopback and private addresses on this computer are accepted; public links must use the host browser.",
        "environmentId:string url:string",
        json!({"environmentId":"env-ID","url":"http://127.0.0.1:13000"}),
        true,
        None
    );
    method!(
        app_status,
        "Check the running engine, version, local control endpoint and background mode.",
        "",
        json!({}),
        false,
        None
    );
    method!(
        app_show,
        "Open/focus the dashboard, including an engine started headlessly.",
        "",
        json!({}),
        true,
        None
    );
    method!(
        app_quit,
        "Gracefully stop the engine and all of its workloads/publications.",
        "",
        json!({}),
        true,
        Some("Stops all Yougori workloads and closes the desktop engine.")
    );
    method!(jobs_list, "List a bounded durable operation journal without request payloads or secrets. Includes blockers and last progress; interrupted jobs require reconciliation.", "", json!({}), false, None);
    method!(jobs_cancel, "Cooperatively cancel accepted work, close transfer streams and release scoped locks. Cancellation is not rollback; inspect the reported partial-copy outcome.", "jobId:string", json!({"jobId":"job-ID"}), true, Some("Cancels only this accepted operation; partially applied changes may remain."));
    method!(jobs_result, "Read a bounded page of a completed operation's result handle; output truncation never changes successful execution to failure.", "jobId:string cursor?:integer limit?:integer", json!({"jobId":"job-ID","cursor":0,"limit":65536}), false, None);
    method!(cancel_file_transfer, "Cancel an active file transfer for the selected environment. A partial staging copy is not published as a completed import.", "environmentId:string transferId?:string", env.clone(), true, Some("Cancels a file transfer for this environment."));
    method!(get_settings_snapshot, "Read settings with their revision and the exact startup trigger. Sign-in startup is not startup before sign-in.", "", json!({}), false, None);
    method!(patch_settings, "Update only supplied settings after checking expectedRevision; unrelated concurrent settings are preserved.", "patch:object expectedRevision:integer", json!({"patch":{"launchAtStartup":true,"startupHeadless":true},"expectedRevision":0}), true, None);
    method!(get_startup_report, "Read native startup recovery, application and publication readiness by environment; includes provider, storage root and actionable failed stage.", "", json!({}), false, None);
    method!(recover_environment_runtime_report, "Recover only a verified abandoned runtime and check the provider-specific storage/ownership postcondition. readyToStart false means recovery remains blocked.", "environmentId:string confirmed:bool", json!({"environmentId":"env-ID","confirmed":true}), true, Some("Recovers this runtime only after verifying that another live owner will remain untouched."));
    method!(execute_guest_job, "Run a cancellable non-interactive command in a local OCI/CUDA container or built-in microVM; short requests launch and poll bounded separate stdout/stderr buffers. timeoutSeconds limits guest lifetime, not HTTP request time. Execution success is independent of output truncation.", "request:object", json!({"request":{"environmentId":"env-ID","command":"uname -a","timeoutSeconds":86400}}), true, Some("Runs this command in the selected guest; cancellation stops only its owned process group."));
    method!(guest_execution_output, "Read bounded stdout/stderr since byte cursors without reloading output history. executionId is exec-JOB_ID for queued guest execution. Output expires 30 minutes after completion.", "environmentId:string executionId:string stdoutCursor?:integer stderrCursor?:integer limit?:integer", json!({"environmentId":"env-ID","executionId":"exec-job-ID","stdoutCursor":0,"stderrCursor":0,"limit":65536}), false, None);
    method!(cancel_guest_execution, "Cancel only this asynchronous guest process group, retaining bounded output for inspection.", "environmentId:string executionId:string", json!({"environmentId":"env-ID","executionId":"exec-job-ID"}), true, Some("Cancels this guest command without stopping its environment."));
    method!(release_guest_execution, "Release retained output for a completed guest command. Running executions are rejected; cancel them first. At most 32 guest execution sessions are retained for 30 minutes.", "environmentId:string executionId:string", json!({"environmentId":"env-ID","executionId":"exec-job-ID"}), true, None);
    method!(deployment_status, "Read the end-to-end deployment state: saved, running, application, local HTTP, tunnel and public HTTPS readiness. URLs are not proof of health.", "path:string", json!({"path":"yougori.yaml"}), false, None);
    method!(get_environment_health_check, "Read this environment's configured application health probe. A missing probe leaves application readiness unverified.", "environmentId:string", json!({"environmentId":"env-ID"}), false, None);
    method!(set_environment_health_check, "Save an application probe with port, local path, GET/HEAD/POST, expected_status, timeout_seconds, wait_seconds and optional bearer_secret reference. Omit health to remove the saved probe; values never belong in metadata.", "environmentId:string health?:object", json!({"environmentId":"env-ID","health":{"port":8000,"path":"/health","method":"GET","expected_status":200,"timeout_seconds":10,"wait_seconds":120}}), true, Some("Changes this environment's saved health probe and its automatic startup verification; protected references require their authorized scope."));
    method!(publication_preflight, "Check domain availability and listener ownership, then report a precise transition preserving unrelated publications. An optional saved domain resolves its protected listener configuration.", "environmentId:string port:port kind:loopback|local|cloudflare hostPort?:port cloudflare?:object domain?:string", json!({"environmentId":"env-ID","port":3000,"kind":"loopback","hostPort":3000}), false, None);
    method!(host_share_credentials, "Explicitly retrieve this user's selected host-folder access capability. Routine metadata never includes the bearer URL.", "shareId:string", json!({"shareId":"share-ID"}), false, Some("Reveals the selected host-folder access capability."));
    method!(model_preflight, "Inspect model task, architecture, runner compatibility, dependencies and likely resources before creating a runtime or downloading weights. quant chooses a GGUF quantization such as Q4_K_M. resources.workerMemoryGbRecommended estimates total Swarm RAM including 4 GiB for agent/test sandboxes.", "model:string quant?:string folder?:string", json!({"model":"hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0"}), false, None);
    method!(model_support_task, "Prepare an isolated architecture-support skill and public checkpoint request for the selected coding agent. Does not launch an agent or enable unverified code.", "model:string agent:string quant?:string", json!({"model":"hf.co/OWNER/MODEL","agent":"codex"}), true, None);
    method!(set_deployment_secret, "Store a protected application secret binding. Supply value through stdin or a private request file; values are never returned.", "name:string value:string", json!({"name":"api-token","value":"EXAMPLE-NOT-A-SECRET"}), true, Some("Stores this application credential in the user's protected vault."));
    method!(delete_deployment_secret, "Remove a protected deployment secret reference; applications using it require a new binding.", "name:string", json!({"name":"api-token"}), true, Some("Removes this protected application credential."));
    method!(
        jobs_get,
        "Get one operation's status and result. A running job is not completed work. wait (milliseconds, up to 30000) returns as soon as the job finishes.",
        "jobId:string wait?:integer",
        json!({"jobId":"job-ID"}),
        false,
        None
    );
    list
}

/// One grids method's summary: what it is for, the verbs `request.do` takes with the fields of
/// each, and what to know. Fields are as typed, in kebab-case; `?` marks one that may be left out,
/// and a field with a fixed set of answers lists them. Made once per noun.
fn grids_summary(noun: &'static str, about: &str, notes: &str) -> &'static str {
    static MADE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<&'static str, &'static str>>> =
        std::sync::LazyLock::new(Default::default);
    let mut made = MADE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    made.entry(noun).or_insert_with(|| Box::leak(format!("{about} request.do: {}. {notes}", grids_verbs(noun)).into_boxed_str()))
}

/// The verbs of one grids noun, as `request.do` takes them.
fn grids_verbs(noun: &str) -> String {
    crate::grids::verbs_of(noun)
        .iter()
        .map(|verb| {
            let fields: Vec<String> = verb
                .targets
                .iter()
                .map(|field| grids_field(verb.verb, field, false))
                .chain(verb.options.iter().map(|field| grids_field(verb.verb, field, true)))
                .collect();
            if fields.is_empty() { verb.verb.to_owned() } else { format!("{} {{{}}}", verb.verb, fields.join(", ")) }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One field, `?` when it may be left out, with its answers when there is a fixed set of them.
fn grids_field(verb: &str, field: &str, optional: bool) -> String {
    let answers = match (verb, field) {
        (_, "serve") => Some("models|desks|credentials|research"),
        ("delete", "when") => Some("later|now|forget"),
        ("two-step", "step") => Some("on|confirm|off"),
        ("cloud-fallback" | "parking", "step") => Some("set|clear"),
        ("memory", "step") => Some("release|keep"),
        _ => None,
    };
    let mark = if optional { "?" } else { "" };
    match answers {
        Some(answers) => format!("{field}{mark} {answers}"),
        None => format!("{field}{mark}"),
    }
}

pub fn find(name: &str) -> Result<Method, String> {
    methods()
        .into_iter()
        .find(|m| m.name == name)
        .ok_or_else(|| format!("Unknown method '{name}'. Run yougori schema."))
}

impl Method {
    pub fn validate(&self, params: &Value) -> Result<(), String> {
        let fields = params
            .as_object()
            .ok_or("Parameters must be a JSON object")?;
        let definitions = self
            .parameters
            .split_whitespace()
            .map(|s| s.split_once(':').unwrap())
            .collect::<Vec<_>>();
        for key in fields.keys() {
            if !definitions
                .iter()
                .any(|(name, _)| name.trim_end_matches('?') == key)
            {
                return Err(format!("Unknown parameter '{key}' for {}", self.name));
            }
        }
        for (name, kind) in definitions {
            let optional = name.ends_with('?');
            let key = name.trim_end_matches('?');
            let Some(value) = fields.get(key).filter(|v| !v.is_null()) else {
                if optional {
                    continue;
                }
                return Err(format!("Missing parameter '{key}' for {}", self.name));
            };
            let valid = match kind {
                "string" => value.is_string(),
                "string[]" => value.as_array().is_some_and(|items| !items.is_empty() && items.len() <= 256 && items.iter().all(|item| item.as_str().is_some_and(|s| !s.is_empty()))),
                "bool" => value.is_boolean(),
                "object" => value.is_object(),
                "array" => value.is_array(),
                "number" => value.as_f64().is_some_and(f64::is_finite),
                "integer" => value.as_u64().is_some(),
                "port" => value.as_u64().is_some_and(|v| (1..=65535).contains(&v)),
                options => value
                    .as_str()
                    .is_some_and(|v| options.split('|').any(|s| s == v)),
            };
            if !valid {
                return Err(format!("Parameter '{key}' must be {kind}"));
            }
        }
        Ok(())
    }
    pub fn confirmation_for(&self, params: &Value) -> Option<&'static str> {
        // One namespace, one table: what `yougori grids …` asks a person to confirm is read from
        // the verb table itself, so the terminal, the queue and the engine cannot disagree.
        if let Some(noun) = crate::grids::noun_for(self.name) {
            let verb = params["request"]["do"].as_str().unwrap_or_default();
            return crate::grids::find(noun, verb).and_then(|known| known.confirmation);
        }
        if self.name == "host_terminal_action"
            && !matches!(
                params["request"]["action"].as_str(),
                Some("read" | "resize")
            )
        {
            return Some(
                "Starts, controls, or ends a shell on the HOST computer, outside guest isolation.",
            );
        }
        if self.name == "terminal_action" && params["action"] == "write" {
            return Some("Sends input/commands to the guest terminal.");
        }
        if self.name == "micro_vm_apps" && params["action"] != "status" {
            return Some("Changes or runs applications inside the microVM.");
        }
        if matches!(self.name, "neocloud_action" | "runpod_action") {
            return match params["action"].as_str() {
                Some("start") => Some("Starts a provider resource that may incur charges."),
                Some("restart") => Some("Restarts a provider resource, interrupting its workload and potentially incurring charges."),
                Some("delete") => Some("Permanently deletes the provider resource; verify its exact name and backups."),
                _ => None,
            };
        }
        self.confirmation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// PROVES that the grids schema says what the command takes: every verb of every noun, in the
    /// words `request.do` accepts, and nothing that is not one. It was written by hand in
    /// camelCase (addKey, bringBack) that the parser refuses, kept a `limit` verb that was gone and
    /// left out the rented-GPU verbs altogether.
    #[test]
    fn the_grids_schema_lists_exactly_the_verbs_the_command_takes() {
        for noun in crate::grids::NOUNS {
            let summary = find(&format!("grids_{noun}")).unwrap().summary;
            let listed = summary.split(" request.do: ").nth(1).unwrap_or_else(|| panic!("grids_{noun} lists no verbs"));
            for verb in crate::grids::verbs_of(noun) {
                assert!(
                    listed.starts_with(&format!("{} ", verb.verb)) || listed.starts_with(&format!("{},", verb.verb)) || listed.contains(&format!(", {} ", verb.verb)) || listed.contains(&format!(", {},", verb.verb)) || listed.contains(&format!(", {}.", verb.verb)),
                    "grids_{noun} does not list {}: {summary}",
                    verb.verb
                );
            }
        }
        let models = find("grids_models").unwrap().summary;
        for words in ["add-key {app?}", "revoke-key {key}", "gpus", "add-gpu {gpu}", "remove-gpu {gpu}", "stop-gpus", "set {plan, model?, percent?, schedule?, idle-after?, quant?}"] {
            assert!(models.contains(words), "{words}: {models}");
        }
        for camel in ["addKey", "revokeKey", "addTeam", "idleAfter"] {
            assert!(!models.contains(camel), "{camel}: {models}");
        }
        let share = find("grids_share").unwrap().summary;
        assert!(share.contains("bring-back {computer}") && !share.contains("bringBack") && !share.contains("limit"), "{share}");
        assert!(find("grids_people").unwrap().summary.contains("two-step {step on|confirm|off, code?}"));
        // The schema is only text: what the command accepts is what the parser accepts.
        let typed = crate::grids::words::parse(&["models".into(), "add-key".into(), "--app".into(), "billing".into()]).unwrap();
        assert_eq!(typed.params()["request"]["do"], "add-key");
    }
    #[test]
    fn cuda_checks_and_updates_target_the_requested_storage_drive() {
        for name in ["get_cuda_runtime_status","install_cuda_runtime"] {
            let method=find(name).unwrap();
            method.validate(&json!({"storageDrive":"D:\\"})).unwrap();
            method.validate(&json!({})).unwrap();
            assert!(method.validate(&json!({"storageDrive":123})).is_err());
        }
        assert!(find("install_cuda_runtime").unwrap().confirmation.is_some());
    }
    #[test]
    fn every_example_matches_its_contract_and_names_are_unique() {
        let mut names = std::collections::HashSet::new();
        for method in methods() {
            assert!(names.insert(method.name));
            method.validate(&method.example).unwrap();
        }
    }
    #[test]
    fn invalid_or_unknown_parameters_never_silently_widen_access() {
        let copy = find("copy_files_to_environment").unwrap();
        for paths in [json!([]), json!("C:/site"), json!(["C:/site", 1]), json!([""]), json!(vec!["C:/site"; 257])] {
            assert!(copy.validate(&json!({"environmentId":"e","paths":paths})).is_err());
        }
        let publish = find("publish_environment_service").unwrap();
        for params in [
            json!({"environmentId":"e","port":3000,"kind":"public"}),
            json!({"environmentId":"e","port":65536,"kind":"local"}),
            json!({"environmentId":"e","port":3000,"kind":"local","typo":true}),
        ] {
            assert!(publish.validate(&params).is_err());
        }
        assert!(publish.confirmation_for(&publish.example).is_some());
        assert!(find("terminal_action")
            .unwrap()
            .confirmation_for(&json!({"action":"write"}))
            .is_some());
        assert!(find("delete_environment").unwrap().confirmation.is_some());
        assert!(find("reclaim_storage").unwrap().confirmation.is_some());
        assert!(find("reclaim_storage").unwrap().validate(&json!({"path":"C:/"})).is_err());
    }

    #[test]
    fn runpod_billable_and_destructive_operations_require_confirmation() {
        for name in ["runpod_create_endpoint", "runpod_endpoint_run", "runpod_attach", "runpod_volume", "runpod_registry", "runpod_disconnect"] {
            let method = find(name).unwrap();
            assert!(method.mutating, "{name}");
            assert!(method.confirmation_for(&method.example).is_some(), "{name}");
        }
        let action = find("runpod_action").unwrap();
        for name in ["start", "restart", "delete"] {
            let params = json!({"environmentId":"env-ID", "action":name});
            action.validate(&params).unwrap();
            assert!(action.confirmation_for(&params).is_some(), "{name}");
        }
        assert!(action.confirmation_for(&json!({"action":"refresh"})).is_none());
        assert!(action.validate(&json!({"environmentId":"env-ID", "action":"terminate"})).is_err());
        assert!(find("runpod_endpoint_run").unwrap().validate(&json!({"environmentId":"env-ID", "input":"invalid"})).is_err());
        assert!(find("runpod_attach").unwrap().validate(&json!({"kind":"volume", "resourceId":"id"})).is_err());
    }

    /// A kind the validator does not know is read as a list of allowed words, so a parameter
    /// written `sso?:boolean` would only ever accept the literal text "boolean". A kind with no
    /// `|` in it is therefore one of the kinds the validator names, every time.
    #[test]
    fn every_parameter_names_a_kind_the_validator_knows() {
        const KINDS: [&str; 8] = ["string", "string[]", "bool", "object", "array", "number", "integer", "port"];
        for method in methods() {
            for definition in method.parameters.split_whitespace() {
                let (name, kind) = definition.split_once(':').expect("every parameter is name:kind");
                assert!(
                    kind.contains('|') || KINDS.contains(&kind),
                    "{} takes {name} as {kind}, which the validator reads as the only word it will accept",
                    method.name,
                );
            }
        }
    }

    /// Signing in through the company's identity provider sends a JSON boolean, the way the
    /// Access Grid's own sign-in does, and both doors have to take it.
    #[test]
    fn signing_in_with_the_company_account_is_a_yes_rather_than_the_word_boolean() {
        for name in ["desk_login", "access_signin"] {
            let method = find(name).unwrap();
            method.validate(&json!({"invite": "desk-invite:x", "sso": true})).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(method.validate(&json!({"invite": "desk-invite:x", "sso": "yes"})).is_err(), "{name}");
        }
    }
}

#[cfg(test)] mod listen_schema_tests {
    #[test] fn shared_model_recording_flag_accepts_json_booleans() {
        let method=super::find("market_share_model").unwrap();
        for listen in [true,false] {method.validate(&serde_json::json!({"environmentId":"fixture","mode":"free","listen":listen})).unwrap();}
        assert!(method.validate(&serde_json::json!({"environmentId":"fixture","mode":"free","listen":"true"})).is_err());
    }
}
