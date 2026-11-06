use super::RuntimeManager;
use crate::{
    file_import::{transfers, CopyProgress},
    models::{Environment, EnvironmentKind},
};
use futures_util::StreamExt;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
mod integration;
#[cfg(test)]
mod transport_tests;

#[derive(Clone, Copy)]
struct Limits {
    connect: Duration,
    inactivity: Duration,
    total: Duration,
    poll: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            inactivity: Duration::from_secs(90),
            total: Duration::from_secs(12 * 60 * 60),
            poll: Duration::from_secs(1),
        }
    }
}
struct AbortReader(tokio::task::AbortHandle);
impl Drop for AbortReader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Lifecycle coordination never spans this stream. Stop can cancel a copy.
async fn transfer_archive(
    base: &str,
    token: &str,
    id: &str,
    archive: &Path,
    transfer: &str,
    expected_bytes: u64,
    folder: Option<&str>,
    progress: Arc<impl Fn(CopyProgress) + Send + Sync + 'static>,
    cancellation: CancellationToken,
    limits: Limits,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(limits.connect)
        .build()
        .map_err(|_| "Cannot initialize file transfer transport")?;
    let mut input = tokio::fs::File::open(archive)
        .await
        .map_err(|e| e.to_string())?;
    let total = input.metadata().await.map_err(|e| e.to_string())?.len();
    let sent = Arc::new(AtomicU64::new(0));
    let (mut sender, receiver) = tokio::io::duplex(256 * 1024);
    let reader = tokio::spawn(async move {
        let mut buffer = vec![0; 128 * 1024];
        loop {
            let count = input.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            sender.write_all(&buffer[..count]).await?;
        }
        sender.shutdown().await?;
        Ok::<_, std::io::Error>(())
    });
    let _reader_guard = AbortReader(reader.abort_handle());
    let mut url = url::Url::parse(&format!("{base}/v1/files/import"))
        .map_err(|_| "Invalid guest import endpoint")?;
    url.query_pairs_mut()
        .append_pair("id", id)
        .append_pair("transfer", transfer)
        .append_pair("folder", folder.unwrap_or(""))
        // This computer's own copy in may land on one of the sandbox's own volumes (a restore of
        // a setup's backup does); an older agent ignores the parameter.
        .append_pair("volumes", "1");
    let mut progress_url = url::Url::parse(&format!("{base}/v1/files/import/progress"))
        .map_err(|_| "Invalid guest progress endpoint")?;
    progress_url
        .query_pairs_mut()
        .append_pair("id", id)
        .append_pair("transfer", transfer);
    let handed_to_transport = sent.clone();
    let body = tokio_util::io::ReaderStream::new(receiver).map(move |chunk| {
        if let Ok(bytes) = &chunk {
            handed_to_transport.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        chunk
    });
    let start = Instant::now();
    let stream_error = |error: reqwest::Error, fallback: &str| {
        if error.is_timeout() && start.elapsed() >= limits.total {
            format!("YOUGORI_TRANSFER_DEADLINE: transfer {transfer} exceeded its total duration; partial guest data retained")
        } else {
            fallback.to_owned()
        }
    };
    let request = async {
        let mut reply=client.post(url).bearer_auth(token).header(reqwest::header::CONTENT_TYPE,"application/x-tar").header(reqwest::header::CONTENT_LENGTH,total)
            .body(reqwest::Body::wrap_stream(body)).timeout(limits.total).send().await
            .map_err(|error|stream_error(error,"Guest import connection or stream failed; partial contents may remain in the unique import folder"))?;
        let status = reply.status();
        let mut body = Vec::new();
        while let Some(chunk) = reply
            .chunk()
            .await
            .map_err(|error| stream_error(error, "Guest import receipt stream failed"))?
        {
            if body.len() + chunk.len() > 64 * 1024 {
                return Err("The guest returned an oversized copy response".into());
            }
            body.extend_from_slice(&chunk);
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err("This environment uses an older guest agent. Restart it after updating Yougori, then copy again.".into());
        }
        let result: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| "The guest did not return a valid copy receipt")?;
        if !status.is_success() {
            return Err(result["error"]
                .as_str()
                .unwrap_or("Guest copy failed")
                .to_owned());
        }
        let expected = format!(
            "{}/yougori-import-{transfer}",
            folder.unwrap_or("").trim_end_matches('/')
        );
        if result["destination"].as_str() != Some(&expected)
            || result["bytes"].as_u64() != Some(expected_bytes)
        {
            return Err(format!("Copy incomplete at {expected}: the guest did not confirm the expected destination and all file contents"));
        }
        Ok(expected)
    };
    tokio::pin!(request);
    let mut last = Instant::now();
    let mut observed = (0, 0);
    let mut confirmed = 0;
    let mut phase = "connecting";
    let mut interval = tokio::time::interval(limits.poll);
    let result = loop {
        tokio::select! {
            result=&mut request=>break result,
            _=cancellation.cancelled()=>break Err(format!("YOUGORI_OPERATION_CANCELLED: transfer {transfer} cancelled; originals unchanged; partial guest data retained in yougori-import-{transfer}")),
            _=interval.tick()=>{
                let uploaded=sent.load(Ordering::Relaxed);
                if uploaded>0 && phase=="connecting" {phase="sending";}
                let poll=client.get(progress_url.clone()).bearer_auth(token).timeout(Duration::from_secs(2)).send();
                let reply=tokio::select! {value=poll=>value,_=cancellation.cancelled()=>continue};
                if let Ok(mut reply)=reply {if reply.status().is_success() {
                    let read=async {
                        let mut bytes=Vec::new();
                        while let Some(chunk)=reply.chunk().await.map_err(|_|())? {if bytes.len()+chunk.len()>8192{return Err(());}bytes.extend_from_slice(&chunk);}
                        Ok::<_,()>(bytes)
                    };
                    if let Ok(Ok(bytes))=tokio::time::timeout(Duration::from_secs(2),read).await {if let Ok(value)=serde_json::from_slice::<serde_json::Value>(&bytes) {
                        confirmed=confirmed.max(value["confirmedBytes"].as_u64().unwrap_or(0)).min(expected_bytes);
                        phase=match value["phase"].as_str(){Some("extracting")=>"extracting",Some("verifying"|"complete")=>"verifying",_=>phase};
                    }}
                }}
                if (uploaded,confirmed)!=observed {observed=(uploaded,confirmed);last=Instant::now();}
                progress(CopyProgress{phase,completed_bytes:uploaded,total_bytes:total,sent_bytes:Some(uploaded),confirmed_bytes:Some(confirmed),waiting_for:Some(if uploaded<total{"guest accepting archive bytes"}else{"guest extraction and receipt"}.into()),..Default::default()});
                if last.elapsed()>limits.inactivity {break Err(format!("YOUGORI_TRANSFER_INACTIVE: no byte progress for {} seconds in {phase}; sent {uploaded}/{total} archive bytes, guest confirmed {confirmed}/{expected_bytes} file bytes. Partial copy retained as yougori-import-{transfer}; cancel or inspect before retrying.",limits.inactivity.as_secs()));}
                if start.elapsed()>limits.total {break Err(format!("YOUGORI_TRANSFER_DEADLINE: transfer {transfer} exceeded its total duration; partial guest data retained"));}
            }
        }
    };
    reader.abort();
    let _ = reader.await;
    if result.is_err() {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            client
                .post(format!("{base}/v1/files/import/cancel"))
                .bearer_auth(token)
                .json(&serde_json::json!({"id":id,"transfer":transfer}))
                .send(),
        )
        .await;
    } else {
        progress(CopyProgress {
            phase: "verifying",
            completed_bytes: total,
            total_bytes: total,
            sent_bytes: Some(total),
            confirmed_bytes: Some(expected_bytes),
            ..Default::default()
        });
    }
    result
}
impl RuntimeManager {
    pub async fn import_file_archive(
        &self,
        environment: &Environment,
        archive: &Path,
        transfer: &str,
        expected_bytes: u64,
        destination_folder: Option<&str>,
        progress: Arc<impl Fn(CopyProgress) + Send + Sync + 'static>,
    ) -> Result<String, String> {
        if let Some(engine) =
            self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))?
        {
            return Box::pin(engine.import_file_archive(
                environment,
                archive,
                transfer,
                expected_bytes,
                destination_folder,
                progress,
            ))
            .await;
        }
        if environment.kind == EnvironmentKind::FullVm {
            return Err("Use an imported-files drive for full VMs".into());
        }
        let (base, token) = self.workspace_endpoint(environment).await?;
        let cancellation = transfers::find(transfer)
            .map(|op| op.cancellation.clone())
            .unwrap_or_default();
        transfer_archive(
            &base,
            &token,
            environment.runtime_id.as_deref().unwrap_or(&environment.id),
            archive,
            transfer,
            expected_bytes,
            destination_folder,
            progress,
            cancellation,
            Limits::default(),
        )
        .await
    }
}
