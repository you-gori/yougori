use super::*;
use serde::{Serialize, Deserialize};

const SKILL: &str = include_str!("../../../../src/lib/environment-skill-template.txt");

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSkills {
    pub environment_id: String,
    pub skill_path: String,
    pub reference_path: String,
    pub delivery: String,
    pub message: String,
}

/// Each bundle has its own guest directory/drive. User-authored skills and
/// existing files are never replaced, and no host folder is shared.
#[tauri::command]
pub async fn install_environment_skills(
    environment_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<InstalledSkills, String> {
    let env = store.environment(&environment_id)?;
    if env.runtime.starts_with("shared://tunnel/") {
        return serde_json::from_value(crate::remote_access::request_saved(&env, "skills", serde_json::json!({"install":true})).await?).map_err(|_| "Invalid remote Skills installation response".into());
    }
    install(&environment_id, &store, &runtime, &manager).await
}

pub(crate) async fn install(
    environment_id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<InstalledSkills, String> {
    let state = store.snapshot()?;
    let environment = state
        .environments
        .iter()
        .find(|e| e.id == environment_id)
        .ok_or("Environment not found")?;
    if environment.status != EnvironmentStatus::Running {
        return Err("Start this environment before installing Skills. Your existing files have not been changed.".into());
    }
    if !matches!(
        environment.kind,
        EnvironmentKind::Container | EnvironmentKind::MicroVm | EnvironmentKind::FullVm
    ) {
        return Err("Skill installation supports local containers, microVMs and VMs. Connection instructions are still available to copy.".into());
    }
    let shares = manager.host_shares_for(environment_id).await;
    let reference = render(&state, environment_id, &shares)?;
    let root = runtime.storage_root().join("skill-staging");
    let staging = tokio::task::spawn_blocking(move || -> Result<tempfile::TempDir, String> {
        std::fs::create_dir_all(&root).map_err(|e| format!("Prepare Skills: {e}"))?;
        let staging = tempfile::Builder::new()
            .prefix("skills-")
            .tempdir_in(root)
            .map_err(|e| format!("Prepare Skills: {e}"))?;
        write_bundle(staging.path(), &reference)?;
        Ok(staging)
    })
    .await
    .map_err(|e| e.to_string())??;
    let copied = crate::file_import::copy_files(
        environment_id,
        vec![staging
            .path()
            .join("yougori-environment")
            .to_string_lossy()
            .into_owned()],
        store,
        runtime,
        |_| {},
    )
    .await?;
    Ok(installed_paths(
        environment_id,
        &copied.destination,
        copied.delivery,
    ))
}

fn write_bundle(root: &std::path::Path, reference: &str) -> Result<(), String> {
    let bundle = root.join("yougori-environment");
    std::fs::create_dir_all(bundle.join("references")).map_err(|e| e.to_string())?;
    std::fs::write(bundle.join("SKILL.md"), SKILL).map_err(|e| e.to_string())?;
    std::fs::write(bundle.join("references/connections.md"), reference)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn installed_paths(environment_id: &str, destination: &str, delivery: &str) -> InstalledSkills {
    let base = format!("{destination}/yougori-environment");
    InstalledSkills {
        environment_id: environment_id.into(),
        skill_path: format!("{base}/SKILL.md"),
        reference_path: format!("{base}/references/connections.md"),
        delivery: delivery.into(),
        message: if delivery == "drive" {
            "Skills are on the attached YOUGORI drive inside the VM. Open the yougori-environment folder in the guest file manager; the guest chooses its drive letter or mount point. Give SKILL.md to your agent, or copy that folder to your agent's skills directory.".into()
        } else {
            "Skills are inside this environment. Give the SKILL.md path to your agent, or copy the yougori-environment folder to your agent's skills directory.".into()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_has_concise_entrypoint_and_self_contained_reference() {
        let root = tempfile::tempdir().unwrap();
        write_bundle(root.path(), "environment identity and permissions").unwrap();
        let bundle = root.path().join("yougori-environment");
        let skill = std::fs::read_to_string(bundle.join("SKILL.md")).unwrap();
        assert!(skill.split_whitespace().count() < 250);
        assert!(skill.starts_with("---\nname: yougori-environment\n"));
        assert!(skill.contains("references/connections.md"));
        assert_eq!(
            std::fs::read_to_string(bundle.join("references/connections.md")).unwrap(),
            "environment identity and permissions"
        );
        assert!(skill.contains("npm run dev"));
        assert!(skill.contains("Get-Content"));
    }
    #[test]
    fn paths_identify_guest_directory_or_drive_without_inventing_a_drive_letter() {
        let directory = installed_paths("env-a", "/yougori-import-123", "directory");
        assert_eq!(
            directory.skill_path,
            "/yougori-import-123/yougori-environment/SKILL.md"
        );
        let drive = installed_paths("env-b", "YOUGORI · 12345678", "drive");
        assert_eq!(drive.environment_id, "env-b");
        assert!(drive.skill_path.starts_with("YOUGORI · 12345678/"));
        assert!(drive.message.contains("drive letter or mount point"));
    }
}
