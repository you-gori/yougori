//! Parking a desk's data in the company's own bucket while it moves, instead of passing it
//! through the hub. The credentials arrive with the hub's instructions only while this computer
//! packs or unpacks a desk, are used at once and are never written down here.
use object_store::{path::Path as ObjectPath, ObjectStore, ObjectStoreExt, PutPayload};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

/// A bucket and a prefix inside it, ready to use.
pub(crate) struct Bucket {
    store: Box<dyn ObjectStore>,
    prefix: ObjectPath,
}

/// Opens the bucket the hub named: AWS S3 (`s3://bucket/prefix?region=…`), an S3-compatible
/// endpoint (`https://host/bucket/prefix`), or, for tests, a folder (`file:///…`).
pub(crate) fn open(credentials: &Value) -> Result<Bucket, String> {
    let provider = credentials["provider"].as_str().unwrap_or_default();
    let location = credentials["location"].as_str().unwrap_or_default().trim();
    let access_key = credentials["accessKey"].as_str().unwrap_or_default();
    let secret_key = credentials["secretKey"].as_str().unwrap_or_default();
    let url = Url::parse(location).map_err(|error| format!("The parking location is not a URL: {error}"))?;
    let region = url.query_pairs().find(|(name, _)| name == "region").map(|(_, value)| value.into_owned()).unwrap_or_else(|| "us-east-1".into());
    match (provider, url.scheme()) {
        ("awsS3", "s3") => {
            let (store, prefix) = object_store::parse_url_opts(&url, [("aws_access_key_id", access_key), ("aws_secret_access_key", secret_key), ("aws_region", region.as_str())]).map_err(|error| format!("Cannot open the parking bucket: {error}"))?;
            Ok(Bucket { store, prefix })
        }
        ("s3Compatible", "http" | "https") => {
            let host = url.host_str().ok_or("The parking location is missing a host")?;
            let mut segments = url.path_segments().ok_or("The parking location is missing a bucket")?.filter(|value| !value.is_empty());
            let bucket = segments.next().ok_or("The parking location needs the bucket as its first path")?;
            let prefix = segments.collect::<Vec<_>>().join("/");
            let endpoint = match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            };
            let store = object_store::aws::AmazonS3Builder::new()
                .with_endpoint(endpoint)
                .with_bucket_name(bucket)
                .with_region(region)
                .with_access_key_id(access_key)
                .with_secret_access_key(secret_key)
                .with_virtual_hosted_style_request(false)
                .with_allow_http(url.scheme() == "http")
                .build()
                .map_err(|error| format!("Cannot open the parking bucket: {error}"))?;
            Ok(Bucket { store: Box::new(store), prefix: ObjectPath::parse(prefix).map_err(|error| error.to_string())? })
        }
        // A folder stands in for a bucket in tests and on an air-gapped network share.
        ("folder", "file") => {
            let (store, prefix) = object_store::parse_url(&url).map_err(|error| format!("Cannot open the parking folder: {error}"))?;
            Ok(Bucket { store, prefix })
        }
        _ => Err("Parking is awsS3 (s3://…), s3Compatible (https://…) or a folder (file://…)".into()),
    }
}

impl Bucket {
    fn key(&self, name: &str) -> Result<ObjectPath, String> {
        let value = if self.prefix.as_ref().is_empty() { name.to_owned() } else { format!("{}/{name}", self.prefix) };
        ObjectPath::parse(value).map_err(|error| error.to_string())
    }

    /// Uploads a file in parts, returning its size and SHA-256.
    pub(crate) async fn put(&self, name: &str, path: &std::path::Path) -> Result<(u64, String), String> {
        use tokio::io::AsyncReadExt;
        let key = self.key(name)?;
        let mut file = tokio::fs::File::open(path).await.map_err(|_| "The packed desk could not be read")?;
        let mut upload = self.store.put_multipart(&key).await.map_err(|error| format!("The parking bucket refused the upload: {error}"))?;
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut part = vec![0u8; 16 * 1024 * 1024];
        loop {
            let mut filled = 0usize;
            while filled < part.len() {
                let read = file.read(&mut part[filled..]).await.map_err(|_| "The packed desk could not be read")?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            if filled == 0 {
                break;
            }
            hash.update(&part[..filled]);
            total += filled as u64;
            upload.put_part(PutPayload::from(part[..filled].to_vec())).await.map_err(|error| format!("The parking bucket dropped the upload: {error}"))?;
        }
        upload.complete().await.map_err(|error| format!("The parking bucket did not finish the upload: {error}"))?;
        Ok((total, hex::encode(hash.finalize())))
    }

    /// Downloads an object to a file, returning what it hashed to.
    pub(crate) async fn get(&self, name: &str, path: &std::path::Path, expected_bytes: u64) -> Result<String, String> {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;
        let key = self.key(name)?;
        let object = self.store.get(&key).await.map_err(|error| format!("The desk's data is not in the parking bucket: {error}"))?;
        let mut stream = object.into_stream();
        let mut file = tokio::fs::File::create(path).await.map_err(|_| "Could not store the desk's data; check free disk space")?;
        let mut hash = Sha256::new();
        let mut total = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| format!("The download from the parking bucket was interrupted: {error}"))?;
            total += chunk.len() as u64;
            if total > expected_bytes {
                return Err("The desk's data in the bucket is larger than expected".into());
            }
            hash.update(&chunk);
            file.write_all(&chunk).await.map_err(|_| "Could not store the desk's data; check free disk space")?;
        }
        file.sync_all().await.map_err(|error| error.to_string())?;
        if total != expected_bytes {
            return Err("The desk's data in the bucket was cut short".into());
        }
        Ok(hex::encode(hash.finalize()))
    }

    /// Removes an object once its desk is unpacked, or when the desk is gone.
    pub(crate) async fn delete(&self, name: &str) -> Result<(), String> {
        let key = self.key(name)?;
        match self.store.delete(&key).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(format!("Could not remove the desk's data from the parking bucket: {error}")),
        }
    }
}

/// The object a desk parks as: one per desk and move, under the grid.
pub(crate) fn object_name(grid: &str, desk: &str, at: i64) -> String {
    format!("yougori-desks/{grid}/{desk}-{at}.yougori-backup")
}
