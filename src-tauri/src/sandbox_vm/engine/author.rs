//! Owner-selected VM capture and in-VM application start. No author code runs on the host.
use super::*;
use yougori_setup::{author, format::Files};

impl Production {
    pub(super) fn capture_template(&self, params: &Value) -> Result<Value, String> {
        let names = params["sandboxes"].as_array().ok_or("Select Sandbox VMs first.")?;
        if names.is_empty() || names.len() > 16 { return Err("Select between 1 and 16 Sandbox VMs.".into()); }
        let name = string(params, "name").unwrap_or_else(|| "my-template".into());
        let connections = self.connection_views();
        let publications = self.publication_views();
        let mut captured = Vec::new();
        let mut total_bytes = 0;
        let mut total_files = 0;
        for selected in names {
            let id = sandbox_id(&json!({"sandbox":selected}))?;
            let record = self.state_file.parent().ok_or("State directory unavailable")?.join(combine::LAUNCHES_DIRECTORY)
                .join(format!("{}.json", id.execution().as_str()));
            let launch: Value = serde_json::from_slice(&fs::read(record).map_err(|_| "This VM has no saved launch settings. Launch it with this version first.")?).map_err(|e| e.to_string())?;
            let workspace = self.workspaces().open(id.execution())?.ok_or("This VM has no workspace. Add its source files first.")?;
            let (bytes, _) = workspace.read_produced(".yougori/setup.json", 128 << 10)
                .map_err(|_| format!("{id}: no setup declaration. Run the app's Yougori setup declaration in its workspace first."))?;
            let definition = author::definition(&bytes)?;
            let mut files = Files::new();
            for path in &definition.files {
                let (bytes, _) = workspace.read_produced(path, 5 << 20)?;
                total_bytes += bytes.len(); total_files += 1;
                if total_bytes > 24 << 20 || total_files > 950 { return Err("The selected source exceeds the Hub package limit. Select fewer source files.".into()); }
                files.insert(path.clone(), bytes);
            }
            let settings = &launch["params"];
            if settings["routes"].as_array().is_some_and(|routes| !routes.is_empty()) {
                return Err(format!("{id}: custom relay routes are not portable in this capture flow. Remove those routes and declare recipient API credentials in the setup code before exporting."));
            }
            captured.push(author::Captured {
                gpu: settings["gpu"] == true,
                id: id.to_string(), definition, files,
                cpu: settings["cpu"].as_u64().unwrap_or(1) as u16,
                memory_gb: settings["memoryGb"].as_f64().unwrap_or(1.0),
                internet: settings["internet"] == true,
                publish: publications[id.as_str()]["declared"].as_array().cloned().unwrap_or_default(),
                connect: connections[id.as_str()]["endpoints"].as_array().cloned().unwrap_or_default(),
            });
        }
        let files = author::package(&name, &captured)?;
        let findings = yougori_cli::hub::scan::scan(&files);
        if !findings.refused.is_empty() { return Err(format!("Export refused by the credential scan: {}", findings.refused.join("; "))); }
        let digest = yougori_cli::hub::scan::digest_of(&files);
        let checked = yougori_setup::format::template(&files).map_err(|e| format!("{e:?}"))?;
        let review = yougori_setup::plan::published_review(&yougori_setup::plan::Package::local(checked), &[])?;
        let operation = params["operation"].as_str().unwrap_or("preview");
        let mut result = json!({"digest":digest,"review":review,"files":files.keys().collect::<Vec<_>>(),
            "sandboxes":captured.iter().map(|vm| json!({"id":vm.id,"name":vm.definition.name,"files":vm.files.len(),
                "connections":vm.connect.iter().filter_map(|edge| captured.iter().find(|other| edge["granted"]["state"] == "active" && edge["granted"]["sandbox"] == other.id).map(|other| other.definition.name.clone())).collect::<Vec<_>>()
            })).collect::<Vec<_>>(),
            "questions":captured.iter().enumerate().flat_map(|(i, vm)| vm.definition.questions.iter().map(move |q| json!({"id":format!("vm{}_{}",i+1,q["id"].as_str().unwrap_or_default()),"question":q["question"],"type":q["type"]}))).collect::<Vec<_>>(),
            "omitted":["Runtime answers, passwords, tokens and application data", "Connections outside the selected VMs", "Host file grants and active public links"]});
        if operation == "export" {
            if params["digest"].as_str() != Some(digest.as_str()) { return Err("The VM source or connections changed. Review the template again before saving.".into()); }
            let folder = PathBuf::from(string(params, "folder").ok_or("Choose an empty destination folder.")?);
            if !folder.is_absolute() || folder.is_file() || folder.is_dir() && fs::read_dir(&folder).map_err(|e| e.to_string())?.next().is_some() {
                return Err("Choose an empty folder with an absolute path; nothing was overwritten.".into());
            }
            yougori_cli::hub::client::write_files(&folder, &files)?;
            result["folder"] = json!(folder);
        } else if operation != "preview" { return Err("Template operation must be preview or export.".into()); }
        Ok(result)
    }

    pub(super) fn start_application(&self, params: &Value) -> Result<Value, String> {
        let id = sandbox_id(params)?;
        let answers = string(params, "secret").ok_or("Private setup answers are required.")?;
        if answers.len() > 256 << 10 || !serde_json::from_str::<Value>(&answers).is_ok_and(|v| v.is_object()) {
            return Err("Setup answers must be a JSON object under 256 KiB.".into());
        }
        let command: Vec<String> = serde_json::from_value(params["argv"].clone()).map_err(|_| "Application argv is required")?;
        if command.is_empty() || command.len() > 64 || command.iter().any(|part| part.is_empty() || part.len() > 4096 || part.contains('\0')) {
            return Err("Invalid application argv.".into());
        }
        let workspace = self.workspaces().open(id.execution())?.ok_or("Application workspace is missing")?;
        let root = crate::sandbox_contract::files::GrantedRoot::open(&workspace.staging()).map_err(|e| format!("{e:?}"))?;
        // Overlay only the new template's declared source on the private copy. Runtime
        // databases and other undeclared data survive a start or reconfiguration.
        if let Some(source) = string(params, "source") {
            use crate::sandbox_contract::files::{GrantedRoot, GuestName};
            let source = GrantedRoot::open(Path::new(&source)).map_err(|e| e.to_string())?;
            let declaration = GuestName::parse(".yougori/setup.json").map_err(|e| e.to_string())?;
            let bytes = source.read_whole(&declaration, 128 << 10)?;
            let definition = author::definition(&bytes)?;
            for file in &definition.files {
                let file = GuestName::parse(file).map_err(|e| e.to_string())?;
                root.write_authorized(&file, &source.read_whole(&file, 5 << 20)?)?;
            }
            root.write_authorized(&declaration, &bytes)?;
        }
        let path = crate::sandbox_contract::files::GuestName::parse(".yougori/answers.json").map_err(|e| e.to_string())?;
        let mut answers: Value = serde_json::from_str(&answers).map_err(|e| e.to_string())?;
        if params["reuseAnswers"] == true {
            let (saved, _) = workspace.read_produced(".yougori/answers.json", 256 << 10)?;
            let mut saved: Value = serde_json::from_slice(&saved).map_err(|_| "Saved application answers are unreadable")?;
            let old = saved.as_object_mut().ok_or("Saved application answers are not an object")?;
            old.extend(answers.as_object().unwrap().clone());
            answers = saved;
        } else {
            answers["_yougori_generation"] = json!(uuid::Uuid::new_v4().to_string());
        }
        let launch = uuid::Uuid::new_v4().to_string();
        answers["_yougori_launch"] = json!(launch);
        root.write_authorized(&path, &serde_json::to_vec(&answers).map_err(|e| e.to_string())?)?;
        let quote = |text: &str| format!("'{}'", text.replace('\'', "'\"'\"'"));
        let script = format!("cd /run/yougori/workspace && exec {CONFINEMENT_PROBE} setup run -- {}\n", command.iter().map(|arg| quote(arg)).collect::<Vec<_>>().join(" "));
        let request = ExecRequest::new(script.into_bytes(), 4096, Duration::MAX);
        let command = self.service.start_exec(&id, request).map_err(|e| e.to_string())?;
        let started = std::time::Instant::now();
        loop {
            if let Some(outcome) = self.service.try_exec_outcome(&id, command).map_err(|e| e.to_string())? {
                // App output can contain submitted credentials: never put it in a job error.
                return Err(format!("The application stopped during setup (exit {:?}). Check its code inside the VM; no setup answers were logged.", outcome.exit_code));
            }
            if workspace.read_produced(".yougori/launch-ready", 128).is_ok_and(|(bytes, _)| bytes == launch.as_bytes()) {
                // Catch an immediate startup exception after the setup callback.
                std::thread::sleep(Duration::from_millis(250));
                if self.service.try_exec_outcome(&id, command).map_err(|e| e.to_string())?.is_some() {
                    return Err("The application exited immediately after setup. Check its start callback.".into());
                }
                break;
            }
            if started.elapsed() >= Duration::from_secs(60) {
                let _ = self.service.cancel(&id, command);
                return Err("Application setup did not finish within 60 seconds. The command was cancelled; make the setup hook bounded and use Setup.run to start the app.".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(json!({"started":true,"command":command,"sandbox":id}))
    }
}
