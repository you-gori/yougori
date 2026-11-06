//! RAII handles for one HCS compute system. Closing the last handle terminates
//! the VM, including when the helper process is killed.
use serde_json::{json, Value};
use std::{ffi::c_void, ptr};
use windows_sys::Win32::{Foundation::LocalFree, System::HostComputeSystem::*};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn operation(start: impl FnOnce(HCS_OPERATION) -> i32) -> Result<Value, String> {
    unsafe {
        let op = HcsCreateOperation(ptr::null(), None);
        if op.is_null() {
            return Err("HCS could not allocate an operation".into());
        }
        let mut document = ptr::null_mut();
        let started = start(op);
        let code = if started < 0 {
            started
        } else {
            HcsWaitForOperationResult(op, 30_000, &mut document)
        };
        let text = if document.is_null() {
            String::new()
        } else {
            let mut count = 0;
            while *document.add(count) != 0 && count < 4 * 1024 * 1024 {
                count += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(document, count));
            LocalFree(document.cast::<c_void>());
            text
        };
        HcsCloseOperation(op);
        if code < 0 {
            return Err(format!(
                "HCS 0x{:08X}: {}",
                code as u32,
                text.chars().take(1500).collect::<String>()
            ));
        }
        if text.is_empty() {
            Ok(json!({}))
        } else {
            serde_json::from_str(&text).map_err(|e| e.to_string())
        }
    }
}

pub const OWNER: &str = "yougori-sandbox-hcs-v1";
pub const SERVICE: &str = "0000bfff-facb-11e6-bd58-64006a7986d3";

pub fn wait_absent(id: &str) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let query = json!({"Owners":[OWNER]});
        let systems = operation(|op| unsafe {
            HcsEnumerateComputeSystems(wide(&query.to_string()).as_ptr(), op)
        })?;
        let rows = systems
            .as_array()
            .ok_or("HCS enumeration returned an invalid result")?;
        if !rows.iter().any(|row| {
            row["Id"]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(id))
        }) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("HCS has not confirmed VM removal".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub struct ComputeSystem {
    handle: HCS_SYSTEM,
    pub id: String,
    pub runtime: uuid::Uuid,
}

impl ComputeSystem {
    pub fn create(id: &str, configuration: &Value) -> Result<Self, String> {
        let mut handle = ptr::null_mut();
        let result = operation(|op| unsafe {
            HcsCreateComputeSystem(
                wide(id).as_ptr(),
                wide(&configuration.to_string()).as_ptr(),
                op,
                ptr::null(),
                &mut handle,
            )
        });
        if let Err(error) = result {
            if !handle.is_null() {
                unsafe { HcsCloseComputeSystem(handle) };
            }
            return Err(error);
        }
        let mut system = Self {
            handle,
            id: id.into(),
            runtime: uuid::Uuid::nil(),
        };
        let properties = system.properties()?;
        if properties["SystemType"] != "VirtualMachine" {
            return Err("HCS did not create a virtual machine".into());
        }
        system.runtime = properties["RuntimeId"]
            .as_str()
            .ok_or("HCS returned no runtime identity")?
            .parse()
            .map_err(|e: uuid::Error| e.to_string())?;
        Ok(system)
    }
    pub fn start(&self) -> Result<(), String> {
        operation(|op| unsafe { HcsStartComputeSystem(self.handle, op, ptr::null()) }).map(|_| ())
    }
    pub fn properties(&self) -> Result<Value, String> {
        operation(|op| unsafe {
            HcsGetComputeSystemProperties(self.handle, op, wide("{}").as_ptr())
        })
    }
    pub fn enable_gpu(&self) -> Result<(), String> {
        let update = json!({"ResourcePath":"VirtualMachine/ComputeTopology/Gpu", "RequestType":"Update", "Settings":{"AssignmentMode":"Mirror", "AllowVendorExtension":true}});
        operation(|op| unsafe {
            HcsModifyComputeSystem(
                self.handle,
                op,
                wide(&update.to_string()).as_ptr(),
                ptr::null_mut(),
            )
        })
        .map(|_| ())
    }
    pub fn terminate(&mut self) -> Result<(), String> {
        if self.handle.is_null() {
            return Ok(());
        }
        let _result =
            operation(|op| unsafe { HcsTerminateComputeSystem(self.handle, op, ptr::null()) });
        unsafe { HcsCloseComputeSystem(self.handle) };
        self.handle = ptr::null_mut();
        // The API may report an already stopped system. Prove absence separately.
        wait_absent(&self.id)
    }
}
impl Drop for ComputeSystem {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { HcsCloseComputeSystem(self.handle) };
        }
    }
}

pub fn configuration(
    kernel: &std::path::Path,
    initrd: &std::path::Path,
    cpus: u64,
    memory_mib: u64,
) -> Value {
    let access = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    json!({
        "SchemaVersion":{"Major":2,"Minor":2}, "Owner":OWNER,
        "ShouldTerminateOnLastHandleClosed":true,
        "VirtualMachine":{
            "StopOnReset":true,
            "Chipset":{"LinuxKernelDirect":{"KernelFilePath":kernel,"InitRdPath":initrd,"KernelCmdLine":"init=/init rdinit=/init panic=-1 quiet"}},
            "ComputeTopology":{"Memory":{"SizeInMB":memory_mib,"AllowOvercommit":true},"Processor":{"Count":cpus,"ExposeVirtualizationExtensions":false}},
            "Devices":{"HvSocket":{"HvSocketConfig":{"DefaultBindSecurityDescriptor":"D:P","DefaultConnectSecurityDescriptor":"D:P","ServiceTable":{SERVICE:{"BindSecurityDescriptor":access,"ConnectSecurityDescriptor":access,"AllowWildcardBinds":false}}}}}
        }
    })
}
