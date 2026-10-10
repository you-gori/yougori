#requires -Version 7.0
<#
Runs explicit, disposable native integration tests. Does not operate saved user
environments. Public tunnels, CUDA setup, real OS installation, and experimental
legacy sandbox/GPU tests are deliberately not enabled by this default gate.
Logs and a machine-readable result are written to a unique artifacts directory.
#>
param(
    [ValidateSet('smoke', 'workloads', 'host', 'cuda', 'windows', 'installers')][string[]]$Group = @('smoke'),
    [ValidateRange(30, 7200)][int]$TimeoutSeconds = 600,
    [string]$TestBinary,
    [string[]]$Only = @()
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/bounded-test-process.ps1')
$workspace = Split-Path -Parent $PSScriptRoot
Push-Location $workspace
try {
    if (!$IsWindows) { throw 'The bundled runtime integration gate requires Windows x64.' }
    $groups = @{
        smoke = @(
            'runtime::tests::bundled_runtime_warm_verification_uses_the_metadata_cache',
            'commands::vm_creation::tests::vm_creation_real_disk_keeps_the_announced_node_id',
            'runtime::storage::tests::storage_vm_creation_uses_selected_capacity_and_never_shrinks_imports',
            'runtime::vm::tests::vm_cache_cleanup_handles_missing_raw_leaf_and_preserves_backing_images',
            'runtime::vm_security::tests::secure_vm_backups_preserve_identity_and_roll_back',
            'commands::factory_reset::tests::factory_reset_vm_preserves_installer_and_recovers_commit',
            'runtime::recovery::windows::tests::recovery_stops_only_an_orphan_with_the_exact_disk',
            'runtime::recovery::windows::tests::vm_recovery_stops_only_an_orphan_with_the_exact_disk',
            'runtime::vm::tests::bundled_qemu_exposes_qmp_and_vnc_websocket',
            'runtime::vm::tests::bundled_alpine_micro_vm_exposes_qmp_without_a_display',
            'runtime::microvm_network::tests::microvm_internet_toggle_preserves_control_and_host_access',
            'runtime::boot_media::tests::installer_boot_generic_iso_and_installed_disk_priority',
            'runtime::boot_media::tests::installer_guest_restarts_keep_process_console_and_installed_disk',
            'runtime::boot_media::tests::installer_guest_restarts_with_secure_boot',
            'runtime::boot_media::tests::secure_boot_rejects_unsigned_installer'
        )
        workloads = @(
            'runtime::storage_reclaim::tests::deletion_reclaims_disk_blocks_and_preserves_peer',
            'automation::tests::automation_real_cli_lifecycle_and_connections',
            'runtime::appliance::tests::bundled_appliance_runs_snapshots_and_enforces_connections',
            'runtime::container_smoke_tests::container_capacity_grows_without_losing_data_or_restarting_active_workloads',
            'runtime::container_smoke_tests::service_images_start_their_default_processes',
            'runtime::storage::tests::storage_expansion_preserves_microvm_files',
            'commands::factory_reset::tests::factory_reset_native_guests_erase_only_target_data',
            'local_backup::tests::real_container_local_backup_round_trip',
            'local_backup::tests::real_micro_vm_local_backup_round_trip',
            'workspace::runtime_tests::workspace_container_end_to_end',
            'workspace::runtime_tests::workspace_microvm_end_to_end',
            'workspace::runtime_tests::workspace_fullvm_forwarding_and_viewers',
            'workspace::installers::tests::workspace_installer_real_pty_staging',
            'runtime::fabric::integration::fabric_real_microvms_and_container_exchange_data_without_internet',
            'runtime::fabric::full_vm_test::fabric_full_vm_pc_adapters_support_dhcp_and_private_traffic',
            'runtime::internet_tests::live_container_internet_cable_preserves_process_and_routes',
            'runtime::internet_tests::live_vm_internet_cable_preserves_process_and_display',
            'guest_apps::runtime_tests::micro_vm_graphical_apps_end_to_end'
        )
        cuda = @(
            'runtime::cuda_tests::cuda_storage_reclamation_preserves_peer',
            # The test requires OPENDOCK_CUDA_TEST_ROOT and refuses all paths
            # except the explicitly prepared build/cuda/integration-runtime.
            'runtime::cuda_tests::cuda_application_lifecycle_files_and_real_kernel'
        )
        windows = @(
            # Requires an explicitly selected ISO and test-only WinPE probe.
            # Boots disposable Windows Setup, without installing an OS.
            'runtime::windows_setup_tests::windows_setup_reaches_visible_installer'
        )
        installers = @(
            # Explicit opt-in: downloads upstream tools only in test containers.
            'workspace::installers::tests::workspace_installer_real_upstream_downloads'
        )
        host = @(
            'host_terminal::tests::host_terminal_real_powershell_cli_input_resize_and_owned_cleanup',
            'commands::tests::windows_gpu_sampler_returns_a_bounded_measurement',
            'workspace::cloudflare::tests::windows_vault_round_trip_uses_only_a_unique_test_credential',
            'workspace::cloudflare::tests::installed_account_connector_validates_token_without_connecting',
            'workspace::cloudflare::tests::installed_quick_tunnel_reaches_local_api_with_isolated_config',
            'window_smoke_tests::native_guest_windows_render_through_async_ipc'
        )
    }
    $tests = @($Group | ForEach-Object { $groups[$_] } | Select-Object -Unique)
    if ($Only.Count) {
        foreach ($name in $Only) {
            if ($name -notin $tests) { throw "Test is not in the selected safe groups: $name" }
        }
        $tests = $Only
    }
    if (!$TestBinary) {
        $messages = & cargo test --manifest-path src-tauri/Cargo.toml --lib --no-run --message-format=json
        if ($LASTEXITCODE -ne 0) { throw 'Native test build failed.' }
        $TestBinary = $messages | ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.executable } |
            Select-Object -Last 1 -ExpandProperty executable
    }
    $TestBinary = (Resolve-Path -LiteralPath $TestBinary).Path
    $available = & $TestBinary --ignored --list
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate native integration tests.' }
    foreach ($name in $tests) {
        if ("${name}: test" -notin $available) { throw "Missing integration test: $name" }
    }
    $report = Join-Path $workspace ('artifacts/production-runtime-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $report | Out-Null
    # Windows can lock a running executable against the next Cargo link. Keep
    # the validated build immutable for this run without locking target/deps.
    $copiedTestBinary = Join-Path $report 'native-integration.exe'
    Copy-Item -LiteralPath $TestBinary -Destination $copiedTestBinary
    $TestBinary = $copiedTestBinary
    $records = [Collections.Generic.List[object]]::new()
    foreach ($name in $tests) {
        $tempDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetTempPath()))
        if ($tempDrive.AvailableFreeSpace -lt 4GB) { throw 'Less than 4 GB free on the temporary-files drive. Refusing to fill the disk.' }
        Write-Output "RUN $name"
        $info = [Diagnostics.ProcessStartInfo]::new($TestBinary)
        $info.WorkingDirectory = $workspace
        foreach ($arg in @('--ignored', '--exact', $name, '--nocapture', '--test-threads=1')) { $info.ArgumentList.Add($arg) }
        $capture = Invoke-BoundedTestProcess -StartInfo $info -TimeoutSeconds $TimeoutSeconds -Label $name
        $passed = !$capture.TimedOut -and $capture.ExitCode -eq 0 -and $capture.SuccessMarker -and !$capture.CaptureError -and !$capture.CleanupError
        $result = if ($capture.TimedOut) { 'timeout' } elseif ($passed) { 'passed' } else { 'failed' }
        $log = ($name -replace '::', '_') + '.log'
        [IO.File]::WriteAllText((Join-Path $report $log), $capture.Output)
        $records.Add([ordered]@{
            test = $name; result = $result; seconds = $capture.Seconds; exitCode = $capture.ExitCode; log = $log
            timeoutPhase = $capture.TimeoutPhase; outputTruncated = $capture.OutputTruncated
            stdoutCharacters = $capture.StdoutCharacters; stderrCharacters = $capture.StderrCharacters
            successMarker = $capture.SuccessMarker; captureError = $capture.CaptureError; cleanupError = $capture.CleanupError
        })
        [IO.File]::WriteAllText((Join-Path $report 'results.json'), (ConvertTo-Json -InputObject @($records.ToArray()) -Depth 5))
        Write-Output "$($result.ToUpperInvariant()) $name ($($capture.Seconds)s)"
        if (!$passed) { Write-Output $capture.Output }
    }
    Write-Output "Results: $report"
    Remove-Item -LiteralPath $copiedTestBinary -Force
    if (@($records | Where-Object result -ne 'passed').Count) { exit 1 }
} finally { Pop-Location }
