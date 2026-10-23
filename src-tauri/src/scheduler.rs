use crate::models::{
    Environment, EnvironmentKind, EnvironmentStatus, HostMetrics, HostPressure, PlatformState,
    Priority, ResourceRange, RuntimeProviderKind,
};

/// Reserve memory for the host and the appliance control plane. Policies may
/// declare a host-sized ceiling; actual allocations must fit this shared budget.
pub const APPLIANCE_OVERHEAD_GB: f64 = 0.375;
pub fn container_capacity(host: &HostMetrics) -> (f64, f64) {
    let reserve = (host.total_memory_gb * 0.1).max(1.0);
    (host.total_cpu.min(255) as f64,
     ((host.total_memory_gb - reserve - APPLIANCE_OVERHEAD_GB).max(0.0) * 8.0).floor() / 8.0)
}

fn is_container(environment: &Environment) -> bool {
    environment.provider.as_ref().is_some_and(RuntimeProviderKind::is_container)
        || (environment.provider.is_none() && environment.kind == EnvironmentKind::Container)
}

pub(crate) fn fixed_vm_resources(environment: &Environment) -> bool {
    fixed_guest_resources(environment, cfg!(target_os = "macos"))
}

fn fixed_guest_resources(environment: &Environment, macos: bool) -> bool {
    macos && matches!(environment.kind, EnvironmentKind::FullVm | EnvironmentKind::MicroVm)
}

fn priority_weight(priority: &Priority) -> f64 {
    match priority {
        Priority::Low => 0.7,
        Priority::Normal => 1.0,
        Priority::High => 1.35,
        Priority::Critical => 1.8,
    }
}

fn allocate(range: &ResourceRange, weight: f64, pressure: &HostPressure) -> f64 {
    let target = match pressure {
        // The same floor as under moderate pressure: an idle host never gives less than a busier one.
        HostPressure::Low => range.preferred * weight.clamp(0.8, 1.25),
        HostPressure::Moderate => range.preferred * (0.85 * weight).clamp(0.8, 1.1),
        HostPressure::High => range.min + (range.preferred - range.min) * 0.25 * weight.min(1.0),
    };
    target.clamp(range.min, range.max)
}

fn quantize_down(value: f64, step: f64, range: &ResourceRange) -> f64 {
    // Decimal CPU steps such as 0.15 / 0.05 can fall just below an integer.
    ((((value / step + 1e-9).floor() * step) * 1e9).round() / 1e9)
        .clamp(range.min, range.max)
}

/// WSL can have less RAM/CPU than the host. Respect that additional pool limit
/// without modifying the user's saved min/preferred/max policy or other engines.
pub fn limit_cuda_pool(state: &mut PlatformState, cpu: f64, memory: f64) -> Result<(), String> {
    let mut running = Vec::new();
    let mut cpu_floor = 0.0;
    let mut memory_floor = 0.0;
    for (index, env) in state.environments.iter().enumerate().filter(|(_,e)| e.provider == Some(RuntimeProviderKind::YougoriCuda)) {
        if env.status == EnvironmentStatus::Running {
            cpu_floor += env.resource_policy.cpu.min;
            memory_floor += env.resource_policy.memory_gb.min;
            running.push(index);
        } else if env.status == EnvironmentStatus::Paused {
            memory_floor += env.resource_policy.memory_gb.current.max(env.resource_policy.memory_gb.preferred);
        }
    }
    if !cpu.is_finite() || !memory.is_finite() || cpu_floor > cpu + 1e-9 || memory_floor > memory + 1e-9 {
        return Err(format!("The CUDA runtime has a shared budget of {cpu:.0} CPUs and {memory:.3} GB after its own reserve. WSL may have less RAM than your PC. Lower CUDA container minimums or stop another CUDA container. Yougori does not change global WSL settings."));
    }
    running.sort_by(|a,b| state.environments[*b].resource_policy.priority.cmp(&state.environments[*a].resource_policy.priority));
    let mut cpu_left = (cpu-cpu_floor).max(0.0);
    let mut memory_left = (memory-memory_floor).max(0.0);
    for index in running {
        let policy = &mut state.environments[index].resource_policy;
        let next_cpu = quantize_down(policy.cpu.min + cpu_left.min((policy.cpu.current-policy.cpu.min).max(0.0)), 0.05, &policy.cpu);
        let next_memory = quantize_down(policy.memory_gb.min + memory_left.min((policy.memory_gb.current-policy.memory_gb.min).max(0.0)), 0.125, &policy.memory_gb);
        cpu_left = (cpu_left-(next_cpu-policy.cpu.min)).max(0.0);
        memory_left = (memory_left-(next_memory-policy.memory_gb.min)).max(0.0);
        policy.cpu.current = next_cpu;
        policy.memory_gb.current = next_memory;
    }
    Ok(())
}

pub fn schedule(state: &mut PlatformState) {
    let running_cuda: Vec<(usize, f64, f64)> = state.environments.iter().enumerate()
        .filter(|(_, e)| e.provider == Some(RuntimeProviderKind::YougoriCuda) && e.status == EnvironmentStatus::Running)
        .map(|(index, e)| (index, e.resource_policy.cpu.current, e.resource_policy.memory_gb.current))
        .collect();
    schedule_for_host(state, cfg!(target_os = "macos"));
    // GPU containers share what WSL can give, which plain scheduling does not know. Every
    // scheduling caps them to the budget the last refresh read, so a save or a start never
    // writes limits WSL cannot honour (it would kill processes inside them).
    if let Some((cpus, memory)) = state.cuda_capacity {
        if limit_cuda_pool(state, cpus, memory).is_err() {
            // Not even their minimums fit: keep what they had rather than ask for more.
            for (index, cpu, memory) in running_cuda {
                if cpu > 0.0 && memory > 0.0 {
                    state.environments[index].resource_policy.cpu.current = cpu;
                    state.environments[index].resource_policy.memory_gb.current = memory;
                }
            }
        }
    }
}

/// The CPU and memory the GPU containers' allocations add up to, counted as `limit_cuda_pool`
/// counts them: running ones by their allocation, paused ones by the memory they keep.
pub fn cuda_pool_total(state: &PlatformState) -> (f64, f64) {
    state.environments.iter().filter(|e| e.provider == Some(RuntimeProviderKind::YougoriCuda)).fold((0.0, 0.0), |(cpu, memory), e| match e.status {
        EnvironmentStatus::Running => (cpu + e.resource_policy.cpu.current, memory + e.resource_policy.memory_gb.current),
        EnvironmentStatus::Paused => (cpu, memory + e.resource_policy.memory_gb.current.max(e.resource_policy.memory_gb.preferred)),
        _ => (cpu, memory),
    })
}

fn schedule_for_host(state: &mut PlatformState, macos: bool) {
    let mut running_indices: Vec<usize> = state
        .environments
        .iter()
        .enumerate()
        .filter_map(|(index, environment)| {
            (environment.status == EnvironmentStatus::Running && environment.kind != EnvironmentKind::Cloud).then_some(index)
        })
        .collect();
    running_indices.sort_by(|left, right| {
        state.environments[*right]
            .resource_policy
            .priority
            .cmp(&state.environments[*left].resource_policy.priority)
    });

    for environment in &mut state.environments {
        environment.resource_policy.dynamic = true;
        if environment.kind == EnvironmentKind::Cloud {
            environment.resource_policy.cpu.current = 0.0;
            environment.resource_policy.memory_gb.current = 0.0;
            continue;
        }
        if environment.status == EnvironmentStatus::Paused {
            // A paused Mac VM will resume the same vCPUs, not a newly saved
            // preference. Keep that allocation for resume (not in CPU demand).
            if !fixed_guest_resources(environment, macos) {
                environment.resource_policy.cpu.current = 0.0;
            }
            if environment.resource_policy.memory_gb.current <= 0.0 {
                environment.resource_policy.memory_gb.current = environment.resource_policy.memory_gb.preferred;
            }
        } else if environment.status != EnvironmentStatus::Running {
            environment.resource_policy.cpu.current = 0.0;
            environment.resource_policy.memory_gb.current = 0.0;
        } else if fixed_guest_resources(environment, macos) {
            // Preserve the real boot allocation, including when a new policy
            // was saved for the next start. Reserve it in the shared budget.
            if environment.resource_policy.cpu.current <= 0.0 {
                environment.resource_policy.cpu.current = environment.resource_policy.cpu.preferred.round().max(1.0);
            }
            if environment.resource_policy.memory_gb.current <= 0.0 {
                environment.resource_policy.memory_gb.current = environment.resource_policy.memory_gb.preferred;
            }
        } else {
            environment.resource_policy.cpu.current = environment.resource_policy.cpu.min;
            if environment.kind != EnvironmentKind::MicroVm {
                // Never below what it uses now plus a margin: a lower limit makes a container's
                // kernel kill its processes, or a VM's balloon take back pages it is using.
                let used = environment.memory_usage_gb;
                let in_use = if used > 0.0 { (used * 1.1).max(used + 0.125) } else { 0.0 }.min(environment.resource_policy.memory_gb.max);
                environment.resource_policy.memory_gb.current =
                    environment.resource_policy.memory_gb.min.max(in_use);
            } else if environment.resource_policy.memory_gb.current <= 0.0 {
                environment.resource_policy.memory_gb.current =
                    environment.resource_policy.memory_gb.preferred;
            }
        }
    }

    let cpu_floor: f64 = running_indices
        .iter()
        .map(|index| state.environments[*index].resource_policy.cpu.current)
        .sum();
    let memory_floor: f64 = state.environments.iter()
        .filter(|e| matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused))
        .map(|e| e.resource_policy.memory_gb.current)
        .sum();
    let container_cpu_floor: f64 = running_indices
        .iter()
        .filter(|index| is_container(&state.environments[**index]))
        .map(|index| state.environments[*index].resource_policy.cpu.current)
        .sum();
    let container_memory_floor: f64 = state.environments.iter()
        .filter(|e| is_container(e) && matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused))
        .map(|e| e.resource_policy.memory_gb.current)
        .sum();
    let factor = match state.host.pressure {
        HostPressure::Low => 0.9,
        HostPressure::Moderate => 0.78,
        HostPressure::High => 0.62,
    };
    let mut cpu_remaining =
        ((state.host.total_cpu as f64 * factor).max(cpu_floor) - cpu_floor).max(0.0);
    let mut memory_remaining =
        ((state.host.total_memory_gb * factor).max(memory_floor) - memory_floor).max(0.0);
    let (container_cpu_capacity, container_memory_capacity) = container_capacity(&state.host);
    let other_memory_floor: f64 = state.environments.iter()
        .filter(|e| e.kind != EnvironmentKind::Cloud && !is_container(e) && matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused))
        .map(|e| e.resource_policy.memory_gb.current.max(e.resource_policy.memory_gb.preferred)).sum();
    let mut container_cpu_remaining = (container_cpu_capacity - container_cpu_floor).max(0.0);
    let mut container_memory_remaining = (container_memory_capacity - other_memory_floor - container_memory_floor).max(0.0);

    for index in running_indices {
        let environment = &mut state.environments[index];
        if fixed_guest_resources(environment, macos) { continue; }
        let weight = priority_weight(&environment.resource_policy.priority);
        let cpu_target = allocate(
            &environment.resource_policy.cpu,
            weight,
            &state.host.pressure,
        );
        let memory_target = allocate(
            &environment.resource_policy.memory_gb,
            weight,
            &state.host.pressure,
        );
        let mut cpu_extra =
            cpu_remaining.min((cpu_target - environment.resource_policy.cpu.current).max(0.0));
        // Direct-kernel microVMs do not resize RAM live. Keep their boot memory
        // in the host budget, even if a newly saved policy requests less RAM.
        let mut memory_extra = if environment.kind == EnvironmentKind::MicroVm { 0.0 } else {
            memory_remaining.min((memory_target - environment.resource_policy.memory_gb.current).max(0.0))
        };
        if is_container(environment) {
            cpu_extra = cpu_extra.min(container_cpu_remaining);
            memory_extra = memory_extra.min(container_memory_remaining);
        }
        let previous_cpu = environment.resource_policy.cpu.current;
        let previous_memory = environment.resource_policy.memory_gb.current;
        environment.resource_policy.cpu.current = quantize_down(
            previous_cpu + cpu_extra,
            0.05,
            &environment.resource_policy.cpu,
        );
        if environment.kind != EnvironmentKind::MicroVm {
            environment.resource_policy.memory_gb.current = quantize_down(
                previous_memory + memory_extra,
                0.125,
                &environment.resource_policy.memory_gb,
            );
        }
        let assigned_cpu = (environment.resource_policy.cpu.current - previous_cpu).max(0.0);
        let assigned_memory =
            (environment.resource_policy.memory_gb.current - previous_memory).max(0.0);
        cpu_remaining = (cpu_remaining - assigned_cpu).max(0.0);
        memory_remaining = (memory_remaining - assigned_memory).max(0.0);
        if is_container(environment) {
            container_cpu_remaining = (container_cpu_remaining - assigned_cpu).max(0.0);
            container_memory_remaining = (container_memory_remaining - assigned_memory).max(0.0);
        }
    }
}

pub fn pressure(cpu_percent: f64, memory_percent: f64) -> HostPressure {
    if cpu_percent > 82.0 || memory_percent > 88.0 {
        HostPressure::High
    } else if cpu_percent > 68.0 || memory_percent > 76.0 {
        HostPressure::Moderate
    } else {
        HostPressure::Low
    }
}

/// The pressure class after the newest readings (the last of each history). A class changes only
/// when the last two readings agree, so one busy moment resizes nothing; and it leaves a higher
/// class only well below where it entered it (CPU: High from 85 % until under 70 %, Moderate from
/// 68 % until under 55 %), so a load hovering at a threshold does not flip every environment's
/// limits each refresh.
pub fn pressure_after(previous: &HostPressure, cpu_history: &[f64], memory_history: &[f64]) -> HostPressure {
    let (cpu, memory) = (&cpu_history[cpu_history.len().saturating_sub(2)..], &memory_history[memory_history.len().saturating_sub(2)..]);
    if cpu.len() < 2 || memory.len() < 2 {
        return pressure(cpu.last().copied().unwrap_or(0.0), memory.last().copied().unwrap_or(0.0));
    }
    let both = |values: &[f64], test: fn(f64) -> bool| values.iter().all(|value| test(*value));
    let into_high = both(cpu, |v| v >= 85.0) || both(memory, |v| v > 88.0);
    let into_moderate = both(cpu, |v| v > 68.0) || both(memory, |v| v > 76.0);
    let out_of_high = both(cpu, |v| v < 70.0) && both(memory, |v| v < 80.0);
    let out_of_moderate = both(cpu, |v| v < 55.0) && both(memory, |v| v < 68.0);
    match previous {
        HostPressure::High if !out_of_high => HostPressure::High,
        HostPressure::High | HostPressure::Moderate if into_high => HostPressure::High,
        HostPressure::High | HostPressure::Moderate => if out_of_moderate { HostPressure::Low } else { HostPressure::Moderate },
        HostPressure::Low if into_high => HostPressure::High,
        HostPressure::Low if into_moderate => HostPressure::Moderate,
        HostPressure::Low => HostPressure::Low,
    }
}

pub fn update_metrics(state: &mut PlatformState, metrics: HostMetrics) {
    state.host = metrics;
    schedule(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Environment, EnvironmentKind, ResourcePolicy, RuntimeProviderKind};

    fn lightweight_environment() -> Environment {
        Environment {
            id: "env-lightweight".into(),
            name: "Lightweight".into(),
            kind: EnvironmentKind::Container,
            status: EnvironmentStatus::Running,
            runtime: "alpine:latest".into(),
            provider: Some(RuntimeProviderKind::YougoriOci),
            runtime_id: Some("env-lightweight".into()),
            runtime_path: None,
            control_endpoint: None,
            console_endpoint: None,
            container_command: Some("sleep 60".into()),
            network_access: false,
            gpu_access: false,
            sandbox_policy: None,
            last_error: None,
            description: String::new(),
            branch_type: None,
            created_at: "1970-01-01T00:00:00Z".into(),
            last_opened_at: None,
            cpu_usage: 0.0,
            memory_usage_gb: 0.0,
            storage_delta_gb: 0.0,
            storage_limit_gb: None,
            storage_drive: None,
            network_rx_mbps: 0.0,
            resource_policy: ResourcePolicy {
                cpu: ResourceRange {
                    min: 0.1,
                    preferred: 0.25,
                    max: 0.5,
                    current: 0.0,
                },
                memory_gb: ResourceRange {
                    min: 0.125,
                    preferred: 0.25,
                    max: 0.5,
                    current: 0.0,
                },
                priority: Priority::Normal,
                dynamic: true,
            },
        }
    }

    fn gpu_desk(id: &str) -> Environment {
        let mut env = lightweight_environment();
        env.id = id.into();
        env.kind = EnvironmentKind::Container;
        env.provider = Some(RuntimeProviderKind::YougoriCuda);
        env.resource_policy.cpu = ResourceRange { min: 1.0, preferred: 4.0, max: 4.0, current: 0.0 };
        env.resource_policy.memory_gb = ResourceRange { min: 3.0, preferred: 12.0, max: 12.0, current: 0.0 };
        env
    }

    #[test]
    fn two_gpu_desks_never_get_more_than_wsl_can_give_together() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.total_cpu = 16;
        state.host.total_memory_gb = 64.0;
        state.host.pressure = HostPressure::Low;
        state.environments = vec![gpu_desk("desk-a"), gpu_desk("desk-b")];
        // Without the cached budget (as before), plain scheduling asks for 12 + 12 GB.
        schedule(&mut state);
        assert_eq!(cuda_pool_total(&state).1, 24.0);
        // With the budget the refresh read, any later save or start keeps both inside 15.5 GB.
        state.cuda_capacity = Some((8.0, 15.5));
        schedule(&mut state);
        let (cpu, memory) = cuda_pool_total(&state);
        assert!(cpu <= 8.0 && memory <= 15.5, "{cpu} CPUs, {memory} GB");
        assert!(state.environments.iter().all(|e| e.resource_policy.memory_gb.current >= 3.0), "minimums kept");
    }

    #[test]
    fn gpu_containers_over_their_budget_keep_what_they_had() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.total_cpu = 16;
        state.host.total_memory_gb = 64.0;
        let mut desk = gpu_desk("desk-a");
        desk.resource_policy.cpu.current = 2.0;
        desk.resource_policy.memory_gb.current = 6.0;
        state.environments = vec![desk];
        // Not even the 3 GB minimum fits in 1 GB: nothing larger is written.
        state.cuda_capacity = Some((1.0, 1.0));
        schedule(&mut state);
        assert_eq!((state.environments[0].resource_policy.cpu.current, state.environments[0].resource_policy.memory_gb.current), (2.0, 6.0));
    }

    #[test]
    fn a_short_spike_keeps_the_pressure_class_and_a_sustained_one_changes_it() {
        let class = |pressure: HostPressure| match pressure { HostPressure::Low => "low", HostPressure::Moderate => "moderate", HostPressure::High => "high" };
        let calm = [30.0, 30.0];
        assert_eq!(class(pressure_after(&HostPressure::Low, &[40.0, 95.0], &calm)), "low", "one busy reading");
        assert_eq!(class(pressure_after(&HostPressure::Low, &[90.0, 95.0], &calm)), "high", "two in a row");
        assert_eq!(class(pressure_after(&HostPressure::High, &[75.0, 72.0], &calm)), "high", "not yet under 70 %");
        assert_eq!(class(pressure_after(&HostPressure::High, &[65.0, 60.0], &calm)), "moderate");
        assert_eq!(class(pressure_after(&HostPressure::Moderate, &[60.0, 58.0], &calm)), "moderate", "not yet under 55 %");
        assert_eq!(class(pressure_after(&HostPressure::Moderate, &[50.0, 40.0], &calm)), "low");
        assert_eq!(class(pressure_after(&HostPressure::Low, &[30.0], &[90.0])), "high", "the first reading is taken as it is");
    }

    #[test]
    fn a_busy_host_never_takes_memory_an_environment_is_using() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.total_cpu = 8;
        state.host.total_memory_gb = 16.0;
        state.host.pressure = HostPressure::High;
        let mut env = lightweight_environment();
        env.status = EnvironmentStatus::Running;
        env.kind = EnvironmentKind::Container;
        env.provider = Some(RuntimeProviderKind::YougoriOci);
        env.resource_policy.memory_gb = ResourceRange { min: 1.0, preferred: 2.0, max: 8.0, current: 0.0 };
        env.memory_usage_gb = 5.0;
        state.environments = vec![env];
        schedule(&mut state);
        assert!(state.environments[0].resource_policy.memory_gb.current >= 5.5, "{}", state.environments[0].resource_policy.memory_gb.current);
    }

    #[test]
    fn no_priority_gets_more_when_the_host_is_busier() {
        let range = ResourceRange { min: 1.0, preferred: 4.0, max: 4.0, current: 0.0 };
        for priority in [Priority::Low, Priority::Normal, Priority::High, Priority::Critical] {
            let weight = priority_weight(&priority);
            let low = allocate(&range, weight, &HostPressure::Low);
            let moderate = allocate(&range, weight, &HostPressure::Moderate);
            let high = allocate(&range, weight, &HostPressure::High);
            assert!(low >= moderate && moderate >= high, "{priority:?}: {low} {moderate} {high}");
        }
    }

    #[test]
    fn fixed_allocations_survive_host_pressure_and_cuda_pool_limits() {
        for kind in [EnvironmentKind::Container, EnvironmentKind::FullVm, EnvironmentKind::MicroVm] {
            for pressure in [HostPressure::Low, HostPressure::Moderate, HostPressure::High] {
                for priority in [Priority::Low, Priority::Normal, Priority::High, Priority::Critical] {
                    let mut env = lightweight_environment();
                    env.kind = kind.clone();
                    env.provider = Some(if kind == EnvironmentKind::Container { RuntimeProviderKind::YougoriCuda } else { RuntimeProviderKind::Qemu });
                    env.resource_policy.cpu = ResourceRange { min: 2.0, preferred: 2.0, max: 2.0, current: 0.0 };
                    env.resource_policy.memory_gb = ResourceRange { min: 1.5, preferred: 1.5, max: 1.5, current: 0.0 };
                    env.resource_policy.priority = priority;
                    let mut state = PlatformState::seeded().unwrap();
                    state.host.total_cpu = 8;
                    state.host.total_memory_gb = 16.0;
                    state.host.pressure = pressure.clone();
                    state.environments = vec![env];
                    for _ in 0..3 {
                        schedule_for_host(&mut state, false);
                        limit_cuda_pool(&mut state, 4.0, 4.0).unwrap();
                        assert_eq!(state.environments[0].resource_policy.cpu.current, 2.0);
                        assert_eq!(state.environments[0].resource_policy.memory_gb.current, 1.5);
                        // The same through the path every save and start takes, with the budget cached.
                        state.cuda_capacity = Some((4.0, 4.0));
                        schedule(&mut state);
                        assert_eq!(state.environments[0].resource_policy.cpu.current, 2.0);
                        assert_eq!(state.environments[0].resource_policy.memory_gb.current, 1.5);
                        state.cuda_capacity = None;
                    }
                    if kind == EnvironmentKind::Container {
                        assert!(limit_cuda_pool(&mut state, 1.0, 1.0).is_err(), "Insufficient capacity must reject the request, not shrink fixed limits");
                        assert_eq!(state.environments[0].resource_policy.cpu.current, 2.0);
                        assert_eq!(state.environments[0].resource_policy.memory_gb.current, 1.5);
                    }
                }
            }
        }
    }

    #[test]
    fn cuda_pool_respects_wsl_limits_and_leaves_other_engines_untouched() {
        let mut state=PlatformState::seeded().unwrap();
        let original=lightweight_environment();
        let mut a=original.clone();a.id="cuda-a".into();a.provider=Some(RuntimeProviderKind::YougoriCuda);
        let mut b=a.clone();b.id="cuda-b".into();
        for env in [&mut a,&mut b] { env.resource_policy.cpu.current=0.5;env.resource_policy.memory_gb.current=0.5; }
        state.environments=vec![original.clone(),a,b];
        limit_cuda_pool(&mut state,0.35,0.375).unwrap();
        assert_eq!(serde_json::to_value(&state.environments[0]).unwrap(),serde_json::to_value(original).unwrap());
        let cpu:f64=state.environments[1..].iter().map(|e|e.resource_policy.cpu.current).sum();
        let memory:f64=state.environments[1..].iter().map(|e|e.resource_policy.memory_gb.current).sum();
        assert!(cpu<=0.35+1e-9 && memory<=0.375+1e-9);
        for env in &state.environments[1..] { assert_eq!(env.resource_policy.memory_gb.max,0.5);assert!(env.resource_policy.memory_gb.current>=env.resource_policy.memory_gb.min); }
        let before=serde_json::to_value(&state).unwrap();
        assert!(limit_cuda_pool(&mut state,0.1,0.125).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(),before);
        state.environments[1].status=EnvironmentStatus::Paused;
        state.environments[1].resource_policy.memory_gb.current=0.5;
        assert!(limit_cuda_pool(&mut state,1.0,0.5).is_err(),"paused RAM must stay in the budget");
    }

    #[test]
    fn macos_vm_budget_keeps_real_boot_allocation_until_next_start() {
        for kind in [EnvironmentKind::FullVm, EnvironmentKind::MicroVm] {
            let mut state = PlatformState::seeded().unwrap();
            state.host.total_cpu = 8;
            state.host.total_memory_gb = 16.0;
            state.host.pressure = HostPressure::High;
            let mut vm = lightweight_environment();
            vm.kind = kind;
            vm.provider = Some(RuntimeProviderKind::Qemu);
            vm.resource_policy.cpu = ResourceRange { min: 1.0, preferred: 3.0, max: 8.0, current: 0.0 };
            vm.resource_policy.memory_gb = ResourceRange { min: 1.0, preferred: 4.0, max: 8.0, current: 0.0 };
            state.environments = vec![vm, lightweight_environment()];
            schedule_for_host(&mut state, true);
            assert_eq!(state.environments[0].resource_policy.cpu.current, 3.0);
            assert_eq!(state.environments[0].resource_policy.memory_gb.current, 4.0);
            assert!(state.environments[1].resource_policy.cpu.current < 0.25, "container scheduling stays dynamic");
            state.environments[0].resource_policy.cpu.preferred = 1.0;
            state.environments[0].resource_policy.memory_gb.preferred = 2.0;
            schedule_for_host(&mut state, true);
            assert_eq!(state.environments[0].resource_policy.cpu.current, 3.0);
            assert_eq!(state.environments[0].resource_policy.memory_gb.current, 4.0);
            state.environments[0].status = EnvironmentStatus::Paused;
            schedule_for_host(&mut state, true);
            state.environments[0].status = EnvironmentStatus::Running;
            schedule_for_host(&mut state, true);
            assert_eq!(state.environments[0].resource_policy.cpu.current, 3.0);
            state.environments[0].status = EnvironmentStatus::Stopped;
            schedule_for_host(&mut state, true);
            assert_eq!(state.environments[0].resource_policy.memory_gb.current, 0.0);
            state.environments[0].status = EnvironmentStatus::Running;
            schedule_for_host(&mut state, true);
            assert_eq!(state.environments[0].resource_policy.cpu.current, 1.0);
            assert_eq!(state.environments[0].resource_policy.memory_gb.current, 2.0);
        }
    }
    #[test]
    fn cloud_resources_never_consume_the_local_scheduler_budget() {
        let mut local=PlatformState::seeded().unwrap();
        local.environments=vec![lightweight_environment()];
        let mut with_cloud=local.clone();
        let mut cloud=lightweight_environment();
        cloud.id="env-cloud".into();cloud.kind=EnvironmentKind::Cloud;cloud.provider=Some(RuntimeProviderKind::CloudSsh);
        cloud.resource_policy.cpu=ResourceRange{min:128.0,preferred:128.0,max:128.0,current:128.0};
        cloud.resource_policy.memory_gb=cloud.resource_policy.cpu.clone();
        with_cloud.environments.push(cloud);
        schedule(&mut local);schedule(&mut with_cloud);
        assert_eq!(serde_json::to_value(&local.environments[0].resource_policy).unwrap(),serde_json::to_value(&with_cloud.environments[0].resource_policy).unwrap());
        assert_eq!(with_cloud.environments[1].resource_policy.cpu.current,0.0);
        assert_eq!(with_cloud.environments[1].resource_policy.memory_gb.current,0.0);
    }

    #[test]
    fn legacy_disabled_scheduler_does_not_block_per_environment_allocation() {
        let mut saved = serde_json::to_value(PlatformState::seeded().unwrap()).unwrap();
        saved["settings"]["schedulerEnabled"] = serde_json::json!(false);
        let mut state: PlatformState = serde_json::from_value(saved).unwrap();
        state.host.total_cpu = 8;
        state.host.total_memory_gb = 16.0;
        state.host.pressure = HostPressure::High;
        let dynamic = lightweight_environment();
        let mut fixed = lightweight_environment();
        fixed.id = "env-fixed".into();
        fixed.resource_policy.dynamic = false;
        fixed.resource_policy.cpu.current = fixed.resource_policy.cpu.preferred;
        fixed.resource_policy.memory_gb.current = fixed.resource_policy.memory_gb.preferred;
        state.environments = vec![dynamic, fixed];

        schedule(&mut state);

        let dynamic = &state.environments[0].resource_policy;
        assert!(dynamic.cpu.current >= dynamic.cpu.min);
        assert!(dynamic.cpu.current < dynamic.cpu.preferred);
        assert!(dynamic.memory_gb.current >= dynamic.memory_gb.min);
        assert!(dynamic.memory_gb.current < dynamic.memory_gb.preferred);
        let fixed = &state.environments[1].resource_policy;
        assert!(fixed.dynamic);
        assert_eq!(fixed.cpu.current, dynamic.cpu.current);
        assert_eq!(fixed.memory_gb.current, dynamic.memory_gb.current);
        assert!(serde_json::to_value(&state.settings).unwrap().get("schedulerEnabled").is_none());
    }

    #[test]
    fn lightweight_defaults_stay_inside_their_range_at_every_pressure() {
        for pressure in [
            HostPressure::Low,
            HostPressure::Moderate,
            HostPressure::High,
        ] {
            let mut state = PlatformState::seeded().unwrap();
            state.host.total_cpu = 1;
            state.host.total_memory_gb = 1.0;
            state.host.pressure = pressure;
            state.environments = vec![lightweight_environment()];
            schedule(&mut state);
            let policy = &state.environments[0].resource_policy;
            assert!(policy.cpu.current >= policy.cpu.min);
            assert!(policy.cpu.current <= policy.cpu.max);
            assert!(policy.memory_gb.current >= policy.memory_gb.min);
            assert!(policy.memory_gb.current <= policy.memory_gb.max);
        }
    }

    #[test]
    fn micro_vm_keeps_boot_memory_even_with_pending_downsize() {
        for pressure in [HostPressure::Low, HostPressure::Moderate, HostPressure::High] {
            let mut state = PlatformState::seeded().unwrap();
            state.host.total_cpu = 8;
            state.host.total_memory_gb = 16.0;
            state.host.pressure = pressure;
            let mut environment = lightweight_environment();
            environment.kind = EnvironmentKind::MicroVm;
            environment.provider = Some(RuntimeProviderKind::Qemu);
            environment.resource_policy.memory_gb.current = 0.25;
            environment.resource_policy.memory_gb.preferred = 0.125;
            environment.resource_policy.memory_gb.max = 0.125;
            state.environments = vec![environment];
            schedule(&mut state);
            assert_eq!(state.environments[0].resource_policy.memory_gb.current, 0.25);
        }
    }

    #[test]
    fn decimal_cpu_steps_do_not_lose_capacity() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.total_cpu = 8;
        state.host.total_memory_gb = 16.0;
        state.host.pressure = HostPressure::Low;
        let mut environment = lightweight_environment();
        environment.resource_policy.cpu.preferred = 0.15;
        state.environments = vec![environment];
        schedule(&mut state);
        assert_eq!(state.environments[0].resource_policy.cpu.current, 0.15);
    }

    #[test]
    fn shared_appliance_allocations_never_exceed_guest_capacity() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.total_cpu = 16;
        state.host.total_memory_gb = 32.0;
        state.host.pressure = HostPressure::Low;
        state.environments = (0..5)
            .map(|index| {
                let mut environment = lightweight_environment();
                environment.id = format!("env-lightweight-{index}");
                environment.runtime_id = Some(environment.id.clone());
                environment
            })
            .collect();
        schedule(&mut state);
        let cpu: f64 = state
            .environments
            .iter()
            .map(|environment| environment.resource_policy.cpu.current)
            .sum();
        let memory: f64 = state
            .environments
            .iter()
            .map(|environment| environment.resource_policy.memory_gb.current)
            .sum();
        let capacity = container_capacity(&state.host);
        assert!(cpu <= capacity.0);
        assert!(memory <= capacity.1);
    }
    #[test]
    fn larger_allocations_reserve_host_and_paused_vm_memory() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.total_cpu = 16;
        state.host.total_memory_gb = 16.0;
        state.host.pressure = HostPressure::Low;
        let mut container = lightweight_environment();
        container.resource_policy.cpu = ResourceRange { min: 0.5, preferred: 8.0, max: 16.0, current: 0.0 };
        container.resource_policy.memory_gb = ResourceRange { min: 0.5, preferred: 16.0, max: 16.0, current: 0.0 };
        let mut paused = lightweight_environment();
        paused.id = "paused-vm".into();
        paused.kind = EnvironmentKind::FullVm;
        paused.provider = Some(RuntimeProviderKind::Qemu);
        paused.status = EnvironmentStatus::Paused;
        paused.resource_policy.memory_gb = ResourceRange { min: 1.0, preferred: 4.0, max: 8.0, current: 4.0 };
        state.environments = vec![container, paused];
        schedule(&mut state);
        assert_eq!(state.environments[1].resource_policy.memory_gb.current, 4.0);
        assert!(state.environments[0].resource_policy.cpu.current > 2.0);
        assert!(state.environments[0].resource_policy.memory_gb.current > 0.625);
        assert!(state.environments[0].resource_policy.memory_gb.current <= container_capacity(&state.host).1 - 4.0);
    }
    #[test]
    fn high_pressure_never_drops_below_minimum() {
        let mut state = PlatformState::seeded().unwrap();
        state.host.pressure = HostPressure::High;
        schedule(&mut state);
        for environment in state
            .environments
            .iter()
            .filter(|item| item.status == EnvironmentStatus::Running)
        {
            assert!(environment.resource_policy.cpu.current >= environment.resource_policy.cpu.min);
            assert!(
                environment.resource_policy.memory_gb.current
                    >= environment.resource_policy.memory_gb.min
            );
        }
        let floor: f64 = state
            .environments
            .iter()
            .filter(|item| item.status == EnvironmentStatus::Running)
            .map(|item| item.resource_policy.cpu.min)
            .sum();
        let allocated: f64 = state
            .environments
            .iter()
            .filter(|item| item.status == EnvironmentStatus::Running)
            .map(|item| item.resource_policy.cpu.current)
            .sum();
        assert!(allocated <= floor.max(state.host.total_cpu as f64 * 0.62) + 1.0);
    }
}
