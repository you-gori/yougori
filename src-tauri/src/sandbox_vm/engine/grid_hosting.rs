//! Opt-in grid tooling. A failed installation stops the new VM; success means the
//! command and its skill were actually installed, not merely saved as preferences.
use super::*;

pub(super) fn selected(params: &Value) -> Result<Vec<String>, String> {
    let values = match params.get("gridHosting") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(values)) => values,
        _ => return Err("gridHosting must be an array of gpu and sandbox.".into()),
    };
    let mut result = Vec::new();
    for value in values {
        let name = value
            .as_str()
            .ok_or("gridHosting entries must be strings.")?;
        if !matches!(name, "gpu" | "sandbox") || result.iter().any(|v| v == name) {
            return Err("gridHosting must contain only unique gpu and sandbox entries.".into());
        }
        result.push(name.to_owned());
    }
    Ok(result)
}

impl Production {
    pub(super) fn prepare_setup_tools(&self, sandbox: &SandboxId, result: &mut Value) -> Result<(), String> {
        let prepared = (|| {
            self.ensure_author_workspace(sandbox)?;
            let command = format!("{CONFINEMENT_PROBE} setup init\n");
            let outcome = self.service.exec(sandbox, ExecRequest::new(command.into_bytes(), 4096, Duration::from_secs(30)))
                .map_err(|error| format!("Setup package installation: {error}"))?;
            if outcome.exit_code != Some(0) {
                return Err("The VM guest needs the current Yougori setup package. Rebuild/update the guest.".to_owned());
            }
            result["setup_package"] = json!({"installed":true,"languages":["python","javascript","typescript"],"contract":".yougori/setup.json"});
            Ok(())
        })();
        if prepared.is_err() {
            let _ = self.service.stop(sandbox);
            self.lifetimes().release(sandbox);
            self.refresh_authorities();
        }
        prepared
    }

    fn ensure_author_workspace(&self, sandbox: &SandboxId) -> Result<(), String> {
        if self.workspaces().open(sandbox.execution())?.is_none() {
            let folder = self.state_file.parent().ok_or("VM state folder unavailable")?
                .join("author-sources").join(sandbox.execution().as_str());
            fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
            self.stage_workspace(sandbox, &folder)?;
        }
        Ok(())
    }

    pub(super) fn prepare_grid_tools(
        &self,
        sandbox: &SandboxId,
        result: &mut Value,
        resources: &[String],
    ) -> Result<(), String> {
        if resources.is_empty() {
            return Ok(());
        }
        let prepared = (|| {
            let installed = self.install_grid_tools(sandbox, resources)?;
            result["grid_hosting"] = installed;
            if let Some(workspace) = self.workspaces().open(sandbox.execution())? {
                let mut view = workspace.view();
                view["mounted_in_guest_at"] = json!(GUEST_WORKSPACE);
                result["workspace"] = view;
            }
            Ok::<(), String>(())
        })();
        match prepared {
            Ok(()) => Ok(()),
            Err(error) => {
                let stopped = self.service.stop(sandbox);
                self.lifetimes().release(sandbox);
                self.refresh_authorities();
                Err(format!("{error}; new VM stopped: {stopped:?}"))
            }
        }
    }
    pub(super) fn install_grid_tools(
        &self,
        sandbox: &SandboxId,
        resources: &[String],
    ) -> Result<Value, String> {
        self.ensure_author_workspace(sandbox)?;
        // Values were validated before the VM was created. No user string enters shell code.
        let command = format!(
            "{CONFINEMENT_PROBE} grid init --reconfigure --resources {}\n",
            resources.iter().flat_map(|name| if name == "sandbox" { vec!["cpu", "memory"] } else { vec!["gpu"] }).collect::<Vec<_>>().join(",")
        );
        let outcome = self
            .service
            .exec(
                sandbox,
                ExecRequest::new(command.into_bytes(), 16 << 10, Duration::from_secs(30)),
            )
            .map_err(|e| format!("Grid tool installation: {e}"))?;
        if outcome.exit_code != Some(0) {
            return Err(format!(
                "Grid tools could not be installed. Rebuild/update the Sandbox VM guest. {}",
                outcome.output.as_bytes().escape_ascii()
            ));
        }
        Ok(
            json!({"enabled": resources, "command": "yougori grid", "skill": "/run/yougori/workspace/.agents/skills/yougori-grid/SKILL.md", "service": "grid", "port": 8787, "gpu_passthrough": false, "controller_started": false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_is_explicit_and_shell_safe() {
        assert!(selected(&json!({})).unwrap().is_empty());
        assert_eq!(
            selected(&json!({"gridHosting":["gpu","sandbox"]})).unwrap(),
            ["gpu", "sandbox"]
        );
        for value in [
            json!(true),
            json!(["gpu", "gpu"]),
            json!(["gpu; touch /bad"]),
            json!([1]),
        ] {
            assert!(selected(&json!({"gridHosting":value})).is_err());
        }
    }
}
