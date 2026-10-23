//! Code copies use content identities and an atomic managed symlink. Existing user paths are kept.
use super::*;
use std::io::Read;
fn quote(s:&str)->String{format!("'{}'",s.replace('\'',"'\"'\"'"))}
/// `generated_*` count what Python itself writes beside code (see `generated`), which an active
/// copy may gain or rewrite without drifting from its source.
#[derive(Debug)]struct SourceIdentity{hash:String,entries:tempfile::NamedTempFile,files:u64,directories:u64,generated_files:u64,generated_directories:u64}
#[derive(Default)]struct SourceProgress{entries:std::sync::atomic::AtomicU64,bytes:std::sync::atomic::AtomicU64}
#[derive(serde::Serialize,serde::Deserialize)]struct SourceFile{relative:PathBuf,sha256:String}
/// Python's own bytecode caches: `__pycache__` folders and `.pyc` files. The only artifacts a
/// running app may add to or rewrite in its active code folder without that counting as drift.
fn generated(relative:&Path,directory:bool)->bool{
    relative.components().any(|part|part.as_os_str()=="__pycache__")||(!directory&&relative.extension().is_some_and(|extension|extension=="pyc"))
}
fn cancelled(token:&tokio_util::sync::CancellationToken)->Result<(),String>{if token.is_cancelled(){Err("YOUGORI_OPERATION_CANCELLED: project source verification cancelled; originals preserved".into())}else{Ok(())}}
fn identity(path:&Path,token:&tokio_util::sync::CancellationToken,progress:Option<&SourceProgress>)->Result<SourceIdentity,String>{
    use std::io::Write;
    let mut hash=Sha256::new();let mut entries=tempfile::NamedTempFile::new().map_err(|e|e.to_string())?;
    let rules=std::fs::read_to_string(path.join(crate::ignore_rules::FILE_NAME)).ok().map(|text|crate::ignore_rules::Rules::parse(&text));
    fn walk(path:&Path,relative:&Path,root:&Path,rules:Option<&crate::ignore_rules::Rules>,hash:&mut Sha256,entries:&mut std::fs::File,counts:&mut(u64,u64,u64,u64),token:&tokio_util::sync::CancellationToken,progress:Option<&SourceProgress>,depth:usize)->Result<(),String>{
        cancelled(token)?;if let Some(progress)=progress{progress.entries.fetch_add(1,std::sync::atomic::Ordering::Relaxed);}
        if depth>128{return Err("Project file tree exceeds the copy protocol's 128-folder limit".into())}
        let metadata=std::fs::symlink_metadata(path).map_err(|e|e.to_string())?;
        // The same rule the copy uses: links and junctions are skipped, other reparse points
        // (OneDrive files, compressed files) are code like any other file.
        if crate::file_import::linked(&metadata){return Ok(())}
        let resolved=path.canonicalize().map_err(|e|e.to_string())?;
        if !resolved.starts_with(root){return Err("Project source escaped its selected folder".into())}
        if rules.is_some_and(|r|r.ignored(&relative.to_string_lossy().replace('\\',"/"),metadata.is_dir())){return Ok(())}
        hash.update(relative.to_string_lossy().as_bytes());hash.update([0]);
        hash.update([u8::from(metadata.permissions().readonly())]);
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;hash.update((metadata.permissions().mode()&0o777).to_le_bytes());}
        if metadata.is_dir(){
            counts.1+=1;if generated(relative,true){counts.3+=1;}hash.update(b"directory");
            let mut children=std::fs::read_dir(path).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;children.sort_by_key(|e|e.file_name());
            for entry in children{walk(&entry.path(),&relative.join(entry.file_name()),root,rules,hash,entries,counts,token,progress,depth+1)?}
        }else if metadata.is_file(){
            counts.0+=1;if generated(relative,false){counts.2+=1;}hash.update(metadata.len().to_le_bytes());
            let source=crate::file_import::CopyEntry{source:path.into(),resolved,relative:relative.into(),directory:false,bytes:metadata.len(),modified:metadata.modified().ok(),mode:0};
            // The tree walker is recursive. Keep its streaming buffer on the heap so
            // directory depth cannot multiply a large stack allocation.
            let mut file=crate::file_import::open_source(&source)?;let mut file_hash=Sha256::new();let mut buffer=vec![0u8;256*1024];
            loop{cancelled(token)?;let n=file.read(&mut buffer).map_err(|e|e.to_string())?;if n==0{break}if let Some(progress)=progress{progress.bytes.fetch_add(n as u64,std::sync::atomic::Ordering::Relaxed);}hash.update(&buffer[..n]);file_hash.update(&buffer[..n]);}
            let after=file.metadata().map_err(|e|e.to_string())?;
            if after.len()!=metadata.len()||after.modified().ok()!=metadata.modified().ok(){return Err("Project source changed while hashing; retry after saving it".into())}
            serde_json::to_writer(&mut *entries,&SourceFile{relative:relative.into(),sha256:format!("{:x}",file_hash.finalize())}).map_err(|e|e.to_string())?;entries.write_all(b"\n").map_err(|e|e.to_string())?;
        }else{return Err("Project source contains a special file that cannot be copied".into())}
        Ok(())
    }
    let mut counts=(0,0,0,0);walk(path,Path::new(""),&path.canonicalize().map_err(|e|e.to_string())?,rules.as_ref(),&mut hash,entries.as_file_mut(),&mut counts,token,progress,0)?;
    Ok(SourceIdentity{hash:format!("{:x}",hash.finalize()),entries,files:counts.0,directories:counts.1,generated_files:counts.2,generated_directories:counts.3})
}
#[cfg(test)]fn fingerprint(path:&Path)->Result<String,String>{Ok(identity(path,&Default::default(),None)?.hash)}
async fn verified_source(path:PathBuf,token:tokio_util::sync::CancellationToken)->Result<SourceIdentity,String>{
    let task_token=token.child_token();let stop=task_token.clone();
    let progress=std::sync::Arc::new(SourceProgress::default());let source_progress=progress.clone();
    let mut task=tokio::task::spawn_blocking(move||identity(&path,&task_token,Some(&source_progress)));
    let mut tick=tokio::time::interval(std::time::Duration::from_secs(1));let mut last_progress=(0,0);let mut advanced=std::time::Instant::now();
    loop{tokio::select!{biased;
        _=token.cancelled()=>{stop.cancel();task.abort();cancelled(&token)?;unreachable!()},
        result=&mut task=>return result.map_err(|e|e.to_string())?,
        _=tick.tick()=>{let current=(progress.entries.load(std::sync::atomic::Ordering::Relaxed),progress.bytes.load(std::sync::atomic::Ordering::Relaxed));crate::automation::context::progress(json!({"phase":"verifying","stage":"sourceHashing","scannedEntries":current.0,"completedBytes":current.1}));if current!=last_progress{last_progress=current;advanced=std::time::Instant::now();}else if advanced.elapsed()>std::time::Duration::from_secs(120){stop.cancel();task.abort();return Err("YOUGORI_TRANSFER_INACTIVE: project source scanning/hashing made no progress for 120 seconds; original and active code preserved".into())}}
    }}
}
/// Checks a guest copy against its source: every file's checksum and the exact set of files and
/// folders. A fresh copy must match entirely; an active one (`running_app`) may differ only in
/// Python's own bytecode caches, which the app writes beside its code.
async fn verify_guest(app:&AppHandle,id:&str,destination:&str,source:&SourceIdentity,running_app:bool)->Result<(),String>{
    use std::io::BufRead;
    let mut command="set -eu; ".to_owned();
    for line in std::io::BufReader::new(source.entries.reopen().map_err(|e|e.to_string())?).lines(){
        let entry:SourceFile=serde_json::from_str(&line.map_err(|e|e.to_string())?).map_err(|_|"Invalid source checksum receipt")?;
        if running_app&&generated(&entry.relative,false){continue}
        let path=if entry.relative.as_os_str().is_empty(){destination.to_owned()}else{format!("{destination}/{}",entry.relative.to_string_lossy().replace('\\',"/"))};
        let check=format!("digest=$(sha256sum {}); digest=${{digest#\\\\}}; digest=${{digest%% *}}; [ \"$digest\" = {} ] || {{ echo 'Copied source checksum mismatch; staging retained, active code unchanged' >&2; exit 74; }}; ",quote(&path),quote(&entry.sha256));
        if command.len()+check.len()>30000{exec(app,id,command).await?;command="set -eu; ".into();}
        command.push_str(&check);
    }
    if command.len()>9{exec(app,id,command).await?;}
    let (files,directories,skip,file_filter)=if running_app{
        (source.files-source.generated_files,source.directories-source.generated_directories,"-name __pycache__ -prune -o ","! -name '*.pyc' ")
    }else{(source.files,source.directories,"","")};
    exec(app,id,format!("set -eu; [ \"$(find {} {skip}-type f {file_filter}-exec printf x \\; | wc -c | tr -d ' ')\" = {} ] && [ \"$(find {} {skip}-type d -exec printf x \\; | wc -c | tr -d ' ')\" = {} ] || {{ echo 'Copied source tree differs from its prepared identity; staging retained' >&2; exit 74; }}",quote(destination),files,quote(destination),directories)).await
}
async fn active_source_matches(app:&AppHandle,id:&str,binding:&FileBinding,source:&SourceIdentity)->Result<(),String>{
    exec(app,id,format!("[ -L {} ] && [ \"$(readlink {})\" = {} ]",quote(&binding.target),quote(&binding.target),quote(&binding.destination))).await?;
    verify_guest(app,id,&binding.destination,source,true).await
}
async fn exec(app:&AppHandle,id:&str,command:String)->Result<(),String>{
    let result=crate::automation::context::child_scope(call(app,"execute_guest_job",json!({"request":{"environmentId":id,"command":command,"timeoutSeconds":1900}}))).await?;
    if result["exitCode"]!=0{return Err(format!("Project file activation failed for {id}: {}",result["stderr"].as_str().unwrap_or("Guest command did not complete")))}
    Ok(())
}
async fn activate(app:&AppHandle,id:&str,target:&str,destination:&str,previous:Option<&str>,release:bool)->Result<(),String>{
    project_cancelled()?;
    let environment=node(app,id)?;let runtime=app.state::<RuntimeManager>();
    let request=json!({"id":environment.runtime_id.as_deref().unwrap_or(id),"target":target,"destination":destination,"previous":previous,"release":release});
    let operation=crate::automation::context::current();
    let call=tokio::time::timeout(std::time::Duration::from_secs(20),runtime.workspace_request(&environment,"/v1/project-files/activate",request));
    let response=if let Some(operation)=operation{tokio::select!{biased;_=operation.cancellation.cancelled()=>{project_cancelled()?;unreachable!()},result=call=>result}}else{call.await};
    response.map_err(|_|"Project activation acknowledgement timed out; inspect the prepared identity before retrying")??;
    Ok(())
}
pub(super) async fn reconcile(app:&AppHandle,p:&Project,record:&mut Record,k:&str)->Result<(),String>{
    let runtime=app.state::<RuntimeManager>();
    let cancellation=crate::automation::context::current().map(|context|context.cancellation).unwrap_or_default();
    for (name,spec) in &p.environments{
        project_cancelled()?;
        let id=record.ids[name].clone();
        let running=node(app,&id)?.status==EnvironmentStatus::Running;
        let retired=record.files.iter().filter(|(key,binding)|binding.active&&key.starts_with(&format!("{id}/"))&&!spec.files.iter().any(|source|source.target==binding.target)).map(|(key,binding)|(key.clone(),binding.clone())).collect::<Vec<_>>();
        let mut changed=Vec::new();
        for source in &spec.files{
            let path=PathBuf::from(&source.source);
            let source_identity=verified_source(path,cancellation.clone()).await?;
            let fingerprint=source_identity.hash.clone();
            let key=format!("{id}/{}",source.target);
            if let Some(binding)=record.files.get(&key).filter(|old|old.fingerprint==fingerprint&&old.active){
                if running&&active_source_matches(app,&id,binding,&source_identity).await.is_ok(){continue}
                project_cancelled()?;
            }
            changed.push((key,source.clone(),source_identity));
        }
        let setup_fingerprint=spec.setup.as_ref().map(|s|format!("{:x}",Sha256::digest(serde_json::to_vec(s).unwrap())));
        let setup_needed=setup_fingerprint.as_ref().is_some_and(|hash|record.setups.get(&id)!=Some(hash));
        if changed.is_empty()&&!setup_needed&&retired.is_empty(){continue}
        status(app,&id,false).await?;
        let env=node(app,&id)?;
        // Options are kept under the runtime ID, which a factory reset changes.
        let options_id=env.runtime_id.clone().unwrap_or_else(||id.clone());
        let old=runtime.workload_options(&options_id)?;
        // Stage application code before starting a command that depends on that code.
        if env.kind==EnvironmentKind::Container{
            record.staging.insert(id.clone(),true);save_record(&runtime,k,record)?;
            let mut temporary=old.clone();temporary.args=Some(vec!["sleep".into(),"2147483647".into()]);temporary.entrypoint=Some(vec![]);
            runtime.save_workload_options(&options_id,&temporary)?;runtime.update_workload_configuration(&env).await?;
        }
        status(app,&id,true).await?;
        let result=async{
            exec(app,&id,"mkdir -p /yougori/project-files".into()).await?;
            for(key,binding)in retired{
                project_cancelled()?;
                // Release only our own activation link. Original and staged file trees remain.
                activate(app,&id,&binding.target,&binding.destination,None,true).await?;
                record.files.get_mut(&key).unwrap().active=false;save_record(&runtime,k,record)?;
            }
            for(key,source,source_identity)in changed{
                project_cancelled()?;
                let fingerprint=source_identity.hash.clone();
                if let Some(binding)=record.files.get(&key).filter(|old|old.fingerprint==fingerprint&&old.active){
                    if active_source_matches(app,&id,binding,&source_identity).await.is_ok(){continue}
                    project_cancelled()?;
                }
                let prepared=record.files.get(&key).filter(|old|old.fingerprint==fingerprint&&!old.active).cloned();
                let (destination,previous)=if let Some(prepared)=prepared{(prepared.destination,prepared.previous)}else{
                    let operation=crate::automation::context::current();
                    let copied=crate::file_import::copy_files_into(&id,vec![source.source.clone()],Some("/yougori/project-files".into()),&app.state::<PlatformStore>(),&runtime,move|progress|{if let Some(operation)=&operation{if let Ok(value)=serde_json::to_value(progress){(operation.progress)(value)}}}).await?;
                    let basename=Path::new(&source.source).file_name().ok_or("Project source must have a file name")?.to_string_lossy();
                    (format!("{}/{}",copied.destination,basename),record.files.get(&key).map(|b|b.destination.clone()))
                };
                crate::automation::context::progress(json!({"phase":"verifying","stage":"guestChecksums","environmentId":id}));
                verify_guest(app,&id,&destination,&source_identity,false).await?;
                if verified_source(PathBuf::from(&source.source),cancellation.clone()).await?.hash!=fingerprint{return Err("Project source changed across the copy; staging retained and active code preserved".into())}
                // Persist identity before activation; lost output is reconciled without another node or publication.
                record.files.insert(key.clone(),FileBinding{fingerprint,destination:destination.clone(),target:source.target.clone(),active:false,previous});save_record(&runtime,k,record)?;
                let binding=&record.files[&key];activate(app,&id,&source.target,&destination,binding.previous.as_deref(),false).await?;
                record.files.get_mut(&key).unwrap().active=true;save_record(&runtime,k,record)?;
            }
            if setup_needed{
                crate::automation::context::progress(json!({"phase":"setup","environmentId":id}));
                let setup=spec.setup.as_ref().unwrap();
                if let Some(version)=&setup.python_minimum{
                    let script=format!("import sys; required=tuple(map(int,{}.split('.'))); actual=sys.version_info[:2]; print('Python compatibility:',str(actual[0])+'.'+str(actual[1]),'required >=',{}); sys.exit(0 if actual>=required else 64)",quote(version),quote(version));
                    exec(app,&id,format!("python -c {} || {{ echo 'Choose an image with the required Python version before installing this SDK' >&2; exit 64; }}",quote(&script))).await?;
                }
                if !setup.pip.is_empty(){
                    let requirements=serde_json::to_string(&setup.pip).unwrap();
                    let script=format!("import importlib.metadata as m,subprocess,sys; requirements={requirements}; needed=[]\nfor requirement in requirements:\n name,version=requirement.split('=='); base=name.split('[')[0]\n try: installed=m.version(base)\n except m.PackageNotFoundError: installed=None\n if installed!=version: needed.append(requirement)\nif needed: subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-cache-dir',*needed],check=True,timeout=1800)");
                    exec(app,&id,format!("python -c {}",quote(&script))).await?;
                }
                if let Some(command)=&setup.verify_command{exec(app,&id,command.clone()).await?;}
                record.setups.insert(id.clone(),setup_fingerprint.unwrap());save_record(&runtime,k,record)?;
            }
            Ok::<(),String>(())
        }.await;
        let _=status(app,&id,false).await;
        if env.kind==EnvironmentKind::Container{runtime.save_workload_options(&options_id,&old)?;runtime.update_workload_configuration(&env).await?;configure(app,&id,spec,&p.project).await?;record.staging.remove(&id);save_record(&runtime,k,record)?;}
        result?;
    }
    Ok(())
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn nested_source_verification_uses_a_standard_thread_stack(){
        let dir=tempfile::tempdir().unwrap();let root=dir.path().to_owned();let mut nested=root.clone();for _ in 0..24{nested.push("x");std::fs::create_dir(&nested).unwrap();}std::fs::write(nested.join("code.txt"),"nested source").unwrap();
        let worker=std::thread::Builder::new().stack_size(2*1024*1024).spawn(move||fingerprint(&root)).unwrap();assert_eq!(worker.join().unwrap().unwrap().len(),64);
    }
    #[test]fn contents_not_timestamps_drive_managed_code_copies(){let dir=tempfile::tempdir().unwrap();std::fs::write(dir.path().join("app.py"),"before").unwrap();let first=fingerprint(dir.path()).unwrap();std::fs::write(dir.path().join("app.py"),"after!").unwrap();assert_ne!(first,fingerprint(dir.path()).unwrap());assert_eq!(fingerprint(dir.path()).unwrap(),fingerprint(dir.path()).unwrap());}
    #[test]fn ignored_content_does_not_trigger_copy(){let dir=tempfile::tempdir().unwrap();std::fs::write(dir.path().join(".yougoriignore"),"weights/\n").unwrap();std::fs::create_dir(dir.path().join("weights")).unwrap();let first=fingerprint(dir.path()).unwrap();std::fs::write(dir.path().join("weights/model.bin"),"large weights").unwrap();assert_eq!(first,fingerprint(dir.path()).unwrap());}
    #[test]fn project_sources_skip_exactly_the_links_their_copy_skips(){
        let dir=tempfile::tempdir().unwrap();let outside=tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"),"code").unwrap();std::fs::write(outside.path().join("secret.txt"),"outside").unwrap();
        #[cfg(windows)] assert!(std::process::Command::new("cmd").args(["/c","mklink","/J"]).arg(dir.path().join("linked")).arg(outside.path()).output().unwrap().status.success());
        #[cfg(unix)] std::os::unix::fs::symlink(outside.path(),dir.path().join("linked")).unwrap();
        // The identity and the copy must agree, or verification fails every apply after a full copy.
        let identity=identity(dir.path(),&Default::default(),None).unwrap();
        let plan=crate::file_import::plan_copy(&[dir.path().to_string_lossy().into_owned()]).unwrap();
        assert_eq!((identity.files,identity.directories),(1,1));
        assert_eq!((plan.files,plan.skipped_links),(1,1));
    }
    #[test]fn only_python_bytecode_caches_may_change_in_active_code(){
        let dir=tempfile::tempdir().unwrap();let root=dir.path();
        std::fs::write(root.join("app.py"),"print(1)").unwrap();
        std::fs::create_dir(root.join("__pycache__")).unwrap();std::fs::write(root.join("__pycache__/app.cpython-312.pyc"),"bytecode").unwrap();
        std::fs::create_dir(root.join("lib")).unwrap();std::fs::write(root.join("lib/old.pyc"),"bytecode").unwrap();std::fs::write(root.join("lib/sitecustomize.py"),"code").unwrap();
        let identity=identity(root,&Default::default(),None).unwrap();
        assert_eq!((identity.files,identity.generated_files),(4,2));
        assert_eq!((identity.directories,identity.generated_directories),(3,1));
        assert!(generated(Path::new("__pycache__"),true)&&generated(Path::new("pkg/__pycache__/m.cpython-312.pyc"),false)&&generated(Path::new("m.pyc"),false));
        // Anything else an app could drop into its code folder still counts as drift.
        for path in ["sitecustomize.py","lib/extra.pth","node_modules/x/index.js","pyc","a.pyc.py"]{assert!(!generated(Path::new(path),false),"{path}");}
        assert!(!generated(Path::new("lib"),true));
    }
    #[tokio::test]async fn cancelled_source_scan_releases_project_work_without_copying(){let dir=tempfile::tempdir().unwrap();std::fs::write(dir.path().join("app.py"),"before").unwrap();let token=tokio_util::sync::CancellationToken::new();token.cancel();assert!(verified_source(dir.path().into(),token).await.unwrap_err().contains("CANCELLED"));assert_eq!(std::fs::read_to_string(dir.path().join("app.py")).unwrap(),"before");}
}
