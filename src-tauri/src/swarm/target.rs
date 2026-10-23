//! All publisher code and generated reproduction scripts run in the disposable test container.
//! HTTP is performed inside that same offline namespace, never by the host's network client.
use super::super::activity;
use super::*;
use yougori_grid::bounty_project::Target;

fn recipe(worker: &Worker) -> Result<Target, String> {
    let value = if worker.policy["target"].is_object() {
        worker.policy["target"].clone()
    } else if worker.policy["scopeMode"] == "live_target" {
        json!({"kind":"web","setupCommand":worker.policy["setupCommand"].as_str().unwrap_or(""),"startCommand":worker.policy["startCommand"].as_str().unwrap_or(""),"port":worker.policy["targetPort"].as_u64().or_else(||worker.policy["targetPort"].as_str().and_then(|p|p.parse().ok())).unwrap_or(0),"healthPath":worker.policy["healthCheck"].as_str().unwrap_or("/")})
    } else {
        json!({"kind":"source","setupCommand":worker.policy["setupCommand"].as_str().unwrap_or(""),"testCommand":worker.policy["testCommand"].as_str().unwrap_or("")})
    };
    serde_json::from_value::<Target>(value)
        .map_err(|e| e.to_string())?
        .checked()
}
/// A live-URL target: the worker reaches the publisher's self-attested service over the network,
/// so this worker's test sandbox runs with internet on and nothing is booted from source.
fn external(worker: &Worker) -> bool {
    recipe(worker).map(|target| target.kind == "url").unwrap_or(false)
}
pub(super) async fn prepare_target(
    app: &AppHandle,
    worker: &Worker,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let target = recipe(worker)?;
    let id = worker
        .test_environment_id
        .as_deref()
        .ok_or("Missing test sandbox")?;
    let environment = env(app, id)?;
    // A new snapshot invalidates old service metadata, even when the sandbox is reused.
    short(
        app,
        &environment,
        &format!("rm -f {ROOT}/.yougori/target.json {ROOT}/.yougori/target.log"),
    )
    .await?;
    if !target.setup_command.trim().is_empty() {
        activity::emit(
            &worker.id,
            "check",
            json!({"text":"Installing the project's declared dependencies in its test sandbox"}),
        );
        if target.install_network {
            crate::commands::update_container_network(id.into(), true, app.state(), app.state())
                .await?;
        }
        let outcome = run_command(
            app,
            worker,
            &target.setup_command,
            600,
            target.install_network,
            cancel,
        )
        .await;
        // Always close installation access before inspection/probing, including failed/cancelled setup.
        let closed =
            crate::commands::update_container_network(id.into(), false, app.state(), app.state())
                .await;
        if let Err(error) = closed {
            let _ = crate::commands::set_environment_status(
                id.into(),
                EnvironmentStatus::Stopped,
                app.state(),
                app.state(),
            )
            .await;
            return Err(format!(
                "Could not close setup networking; target was stopped: {error}"
            ));
        }
        let receipt = outcome?;
        if receipt["exitCode"] != 0 {
            return Err(format!(
                "Project setup failed: {}",
                crate::lifecycle::safe_diagnostic(
                    receipt["stderr"]
                        .as_str()
                        .unwrap_or("Check the declared setup command")
                )
            ));
        }
    }
    ensure_target(app, worker, cancel).await
}
pub(crate) async fn ensure_target(
    app: &AppHandle,
    worker: &Worker,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let target = recipe(worker)?;
    if target.kind == "source" {
        return Ok(());
    }
    current(app, worker, cancel).await?;
    let id = worker
        .test_environment_id
        .as_deref()
        .ok_or("Missing target sandbox")?;
    if target.kind == "url" {
        return ensure_live_target(app, worker, &target, id, cancel).await;
    }
    let mut environment = env(app, id)?;
    if environment.description != owned_description(worker, true) || environment.network_access {
        return Err("Target requires this worker's offline sandbox".into());
    }
    if environment.status != EnvironmentStatus::Running {
        crate::commands::set_environment_status(
            id.into(),
            EnvironmentStatus::Running,
            app.state(),
            app.state(),
        )
        .await?;
        environment = env(app, id)?;
    }
    stage(
        app,
        &environment,
        &format!("{ROOT}/.yougori/target-recipe.json"),
        serde_json::to_string(&target).unwrap().as_bytes(),
        "444",
    )
    .await?;
    stage(
        app,
        &environment,
        &format!("{ROOT}/.yougori/target-supervisor.py"),
        SUPERVISOR.as_bytes(),
        "444",
    )
    .await?;
    let stop = cancel.child_token();
    let work = job(
        app,
        id,
        format!("python3 {ROOT}/.yougori/target-supervisor.py"),
        75,
        &stop,
    );
    let result = supervise_check(work, &stop, cancel, Duration::from_secs(2), || async {
        let state = super::super::agent(
            app,
            worker,
            reqwest::Method::GET,
            "/api/swarm/agent/state",
            None,
        )
        .await?;
        Ok(super::super::execution_authorized(&state, worker))
    })
    .await?;
    if result["exitCode"] != 0 {
        return Err(format!(
            "Target failed its startup/health check: {}",
            crate::lifecycle::safe_diagnostic(
                result["stderr"]
                    .as_str()
                    .unwrap_or("Check the start command, port and health path")
            )
        ));
    }
    Ok(())
}

/// Prepares a live-URL target: brings this worker's sandbox online (unlike the offline source/web
/// sandbox) and confirms the declared service answers over the network. Nothing is booted here.
async fn ensure_live_target(
    app: &AppHandle,
    worker: &Worker,
    target: &Target,
    id: &str,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let mut environment = env(app, id)?;
    if environment.description != owned_description(worker, true) {
        return Err("Target requires this worker's test sandbox".into());
    }
    if environment.status != EnvironmentStatus::Running {
        crate::commands::set_environment_status(
            id.into(),
            EnvironmentStatus::Running,
            app.state(),
            app.state(),
        )
        .await?;
        environment = env(app, id)?;
    }
    if !environment.network_access {
        crate::commands::update_container_network(id.into(), true, app.state(), app.state()).await?;
    }
    let input = json!({"base": target.base_url, "health": target.health_path});
    let script = HEALTH_PROBE.replace(
        "__INPUT__",
        &format!(
            "json.loads(base64.b64decode('{}'))",
            STANDARD.encode(input.to_string())
        ),
    );
    let params = json!({"language":"python","code":script});
    // The sandbox network was just opened, and DNS and routing take a moment to come up —
    // "Temporary failure in name resolution" is transient by its own definition. Try a few times,
    // a few seconds apart, before deciding the service is unreachable, rather than failing on the
    // very first probe while the network is still settling.
    let mut last = String::new();
    for attempt in 0..5u32 {
        if cancel.is_cancelled() {
            return Ok(());
        }
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let receipt = experiment(app, worker, &params, cancel).await?;
        if receipt["exitCode"] == 0 {
            return Ok(());
        }
        last = receipt["stderr"].as_str().unwrap_or("").to_owned();
    }
    Err(format!(
        "The live target at {} did not answer over the network after several tries: {}",
        target.base_url,
        crate::lifecycle::safe_diagnostic(if last.trim().is_empty() {
            "check the base URL and that the service is reachable from this computer"
        } else {
            &last
        })
    ))
}

pub(crate) async fn experiment(
    app: &AppHandle,
    worker: &Worker,
    params: &Value,
    cancel: &CancellationToken,
) -> Result<Value, String> {
    let language = params["language"].as_str().unwrap_or("");
    let interpreter = match language {
        "python" => "python3",
        "javascript" => "node",
        _ => return Err("Choose python or javascript for a sandbox reproduction".into()),
    };
    let code = params["code"]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= 48000 && !s.contains('\0'))
        .ok_or("Provide a reproduction script of 1–16000 bytes")?;
    let encoded = STANDARD.encode(code);
    // Supply code on stdin; no host-side files, shell interpolation or new network grants.
    let command = format!("printf %s {} | base64 -d | {interpreter}", quote(&encoded));
    let mut result = run_command(app, worker, &command, 120, external(worker), cancel).await?;
    result["receiptId"] = format!("experiment-{}", uuid::Uuid::new_v4().simple()).into();
    result["scriptSha256"] = format!("{:x}", Sha256::digest(code.as_bytes())).into();
    result["sourceRevision"] = worker.policy["sourceRevision"].clone();
    Ok(result)
}
pub(crate) async fn http_probe(
    app: &AppHandle,
    worker: &Worker,
    params: &Value,
    cancel: &CancellationToken,
) -> Result<Value, String> {
    let target = recipe(worker)?;
    if target.kind == "source" {
        return Err(
            "This bounty is source review; its owner did not declare a running service".into(),
        );
    }
    let mut input = http_input(params, target.port)?;
    // Loopback for a sandbox-booted service; the declared origin for a live-URL target.
    input["base"] = if target.kind == "url" {
        json!(target.base_url)
    } else {
        json!(format!("http://127.0.0.1:{}", target.port))
    };
    let script = HTTP_PROBE.replace(
        "__INPUT__",
        &format!(
            "json.loads(base64.b64decode('{}'))",
            STANDARD.encode(input.to_string())
        ),
    );
    let receipt = experiment(
        app,
        worker,
        &json!({"language":"python","code":script}),
        cancel,
    )
    .await?;
    if receipt["exitCode"] != 0 {
        return Err(format!(
            "Sandbox HTTP probe failed: {}",
            receipt["stderr"].as_str().unwrap_or("No receipt")
        ));
    }
    let mut result: Value = serde_json::from_str(receipt["stdout"].as_str().unwrap_or(""))
        .map_err(|_| "Target probe did not return a complete HTTP receipt")?;
    result["request"] = json!({"method":input["method"],"path":input["path"],"session":input["session"],"resetSession":input["resetSession"]});
    result["receiptId"] = receipt["receiptId"].clone();
    result["sourceRevision"] = worker.policy["sourceRevision"].clone();
    Ok(result)
}

fn http_input(params: &Value, port: u16) -> Result<Value, String> {
    if !params.is_object() || params.to_string().len() > 24000 {
        return Err("HTTP probe must be an object no larger than 24 KiB".into());
    }
    let path = params
        .get("path")
        .map_or(Some("/"), Value::as_str)
        .ok_or("Provide a relative target path")?;
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['\\', '\r', '\n', '\0'])
        || path.len() > 4096
    {
        return Err("Use a relative target path, such as /api/orders".into());
    }
    let session = params
        .get("session")
        .map_or(Some("default"), Value::as_str)
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 48
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .ok_or("Use a session name of 1–48 letters, digits, underscores or hyphens")?;
    let reset = params
        .get("resetSession")
        .map_or(Some(false), Value::as_bool)
        .ok_or("resetSession must be true or false")?;
    let method = params
        .get("method")
        .map_or(Some("GET"), Value::as_str)
        .ok_or("Provide an HTTP method")?
        .to_ascii_uppercase();
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        return Err("Unsupported HTTP method".into());
    }
    let mut input = params.clone();
    input["port"] = port.into();
    input["path"] = path.into();
    input["method"] = method.into();
    input["session"] = session.into();
    input["resetSession"] = reset.into();
    Ok(input)
}

const SUPERVISOR: &str = r#"import os,json,subprocess,time,urllib.request,urllib.error,sys
root='/srv/yougori-swarm'
recipe=json.load(open(root+'/.yougori/target-recipe.json'))
state=root+'/.yougori/target.json'
logpath=root+'/.yougori/target.log'
LOG_LIMIT=8*1024*1024
LOG_KEEP=64*1024
def tail(path,count):
 try:
  with open(path,'rb') as f:
   f.seek(0,2); f.seek(max(0,f.tell()-count)); return f.read().decode('utf-8','replace')
 except OSError: return ''
def rotate():
 # The service writes in append mode, so emptying the file simply starts it again from
 # the end: a long-running target cannot fill the sandbox's disk with its log.
 try:
  if os.path.getsize(logpath)>LOG_LIMIT:
   kept=tail(logpath,LOG_KEEP)
   os.truncate(logpath,0)
   with open(logpath,'ab') as f: f.write(('[earlier output dropped]\n'+kept).encode())
 except OSError: pass
def born(pid):
 try: fields=open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()
 except OSError: return None
 # A process that has exited and not been reaped answers nothing; it is not the service.
 if fields[0]=='Z': return None
 return fields[19]
rotate()
try: saved=json.load(open(state))
except (OSError,ValueError): saved={}
if not saved.get('born') or born(saved.get('pid'))!=saved.get('born'):
 open(logpath,'wb').close()
 log=open(logpath,'ab')
 import shlex
 cmd='cd '+root+'/build && exec env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/yougori-test CI=1 HOST=127.0.0.1 PORT='+str(recipe['port'])+' /bin/sh -c '+shlex.quote(recipe['startCommand'])
 child=subprocess.Popen(['su','-s','/bin/sh','yougori-test','-c',cmd],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
 saved={'pid':child.pid,'born':born(child.pid)}
 json.dump(saved,open(state,'w'))
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(120):
 if born(saved['pid'])!=saved['born']: break
 try:
  response=opener.open('http://127.0.0.1:'+str(recipe['port'])+recipe['healthPath'],timeout=.4)
  if 200<=response.status<400: print('Target healthy');sys.exit(0)
 except (OSError,urllib.error.URLError): pass
 time.sleep(.1)
print(tail(logpath,6000),file=sys.stderr)
sys.exit('Service did not pass its health check; review its command and port')
"#;
const HTTP_PROBE: &str = r#"import json,base64,urllib.request,urllib.error,http.cookiejar,os,time,sys
args=__INPUT__
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
os.umask(0o077)
session=args.get('session','default')
jar=None
handlers=[urllib.request.ProxyHandler({}),NoRedirect()]
if session!='anonymous':
 jar=http.cookiejar.LWPCookieJar('/tmp/yougori-target-cookies-'+session)
 if not args.get('resetSession',False):
  try: jar.load(ignore_discard=True)
  except (OSError,ValueError): pass
 handlers.append(urllib.request.HTTPCookieProcessor(jar))
client=urllib.request.build_opener(*handlers)
headers=args.get('headers') or {}
if not isinstance(headers,dict) or len(headers)>32: raise ValueError('At most 32 headers')
data=args.get('body')
base=args.get('base') or ('http://127.0.0.1:'+str(args.get('port',0)))
request=urllib.request.Request(base+args.get('path','/'),data=None if data is None else data.encode(),headers=headers,method=args.get('method','GET').upper())
started=time.monotonic()
try:
 try: response=client.open(request,timeout=10)
 except urllib.error.HTTPError as error: response=error
 raw=response.read(8001)
 result={'status':response.status,'headers':{k[:128]:v[:256] for k,v in list(response.headers.items())[:16]},'body':raw[:8000].decode('utf-8','replace'),'truncated':len(raw)>8000,'seconds':round(time.monotonic()-started,3)}
except (OSError,urllib.error.URLError) as error: result={'status':0,'error':str(error)}
if jar is not None: jar.save(ignore_discard=True)
result['session']=session
encoded=json.dumps(result,ensure_ascii=False)
while len(encoded.encode())>20000:
 result['truncated']=True
 if result.get('body'): result['body']=result['body'][:len(result['body'])//2]
 elif result.get('headers'): result['headers'].pop(next(iter(result['headers'])))
 else: result={'status':0,'error':'HTTP receipt exceeds its limit','truncated':True}
 encoded=json.dumps(result,ensure_ascii=False)
sys.stdout.buffer.write(encoded.encode('utf-8')+b'\n')
"#;
/// Confirms a live-URL target is reachable before investigation. Any HTTP status (including an auth
/// challenge on the health path) means the service answered; only a connection or DNS failure is
/// treated as unreachable.
const HEALTH_PROBE: &str = r#"import json,base64,urllib.request,urllib.error,sys
args=__INPUT__
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
base=(args.get('base') or '').rstrip('/')
health=args.get('health') or '/'
if not health.startswith('/'): health='/'+health
try: opener.open(base+health,timeout=10); sys.exit(0)
except urllib.error.HTTPError: sys.exit(0)
except (OSError,urllib.error.URLError) as error: print(str(error),file=sys.stderr); sys.exit('The service did not answer over the network')
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_sessions_keep_legacy_defaults_and_the_accepted_service_port() {
        let input =
            http_input(&json!({"path":"/login","method":"post","port":9999}), 3000).unwrap();
        assert_eq!(
            input,
            json!({"path":"/login","method":"POST","port":3000,"session":"default","resetSession":false})
        );
        assert_eq!(
            http_input(&json!({"session":"tenant-b","resetSession":true}), 4000).unwrap()
                ["session"],
            "tenant-b"
        );
    }

    #[test]
    fn http_sessions_reject_paths_and_invalid_control_values() {
        for value in [
            json!({"session":"../other"}),
            json!({"session":""}),
            json!({"session":"a".repeat(49)}),
            json!({"session":null}),
            json!({"resetSession":"false"}),
            json!({"path":"https://elsewhere.test"}),
            json!({"method":"CONNECT"}),
            json!([]),
        ] {
            assert!(
                http_input(&value, 3000).is_err(),
                "Unexpectedly accepted {value}"
            );
        }
    }
}
