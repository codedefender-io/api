//! High-level client interface for interacting with the CodeDefender SaaS API.
//!
//! This module provides functions to upload files, analyze binaries, initiate
//! obfuscation, and poll for obfuscation results via blocking HTTP requests.
//!
//! All endpoints require a valid API key, passed via the `Authorization` header
//! using the `ApiKey` scheme.

use codedefender_config::{AnalysisResult, Config};
use reqwest::{blocking::Client, StatusCode};
use std::collections::HashMap;

const UPLOAD_EP: &str = "https://app.codedefender.io/api/upload";
const ANALYZE_EP: &str = "https://app.codedefender.io/api/analyze";
const DEFEND_EP: &str = "https://app.codedefender.io/api/defend";
const DOWNLOAD_EP: &str = "https://app.codedefender.io/api/download";

/// Represents the result of a call to [`download`].
pub enum DownloadStatus {
    /// The obfuscated file is ready and contains the returned bytes.
    Ready(Vec<u8>),

    /// The obfuscation is still in progress.
    Processing,

    /// The download failed due to a network or server error.
    Failed(reqwest::Error),
}

/// Uploads a binary file to CodeDefender and returns a UUID representing the uploaded file.
///
/// # Arguments
///
/// * `file_bytes` - The raw contents of the binary file to upload.
/// * `client` - A preconfigured `reqwest::blocking::Client`.
/// * `api_key` - Your CodeDefender API key.
///
/// # Returns
///
/// A `Result<String, reqwest::Error>` containing the UUID on success, or an error if the upload failed.
///
/// # Errors
///
/// Returns an error if the request fails or if the server responds with a non-success status code (not in 200..=299).
pub fn upload_file(
    file_bytes: Vec<u8>,
    client: &Client,
    api_key: &str,
) -> Result<String, reqwest::Error> {
    let response = client
        .put(UPLOAD_EP)
        .header("Authorization", format!("ApiKey {}", api_key))
        .header("Content-Type", "application/octet-stream")
        .body(file_bytes)
        .send()?;

    response.text()
}

/// Analyzes a previously uploaded binary file and optionally its PDB file.
///
/// # Arguments
///
/// * `file_id` - UUID of the uploaded binary file.
/// * `pdb_file_id` - Optional UUID of the associated PDB file.
/// * `client` - A preconfigured `reqwest::blocking::Client`.
/// * `api_key` - Your CodeDefender API key.
///
/// # Returns
///
/// An `AnalysisResult` containing metadata about the uploaded binary.
///
/// # Errors
///
/// Returns an error if the request fails or the server responds with a non-success status.
/// Panics if JSON deserialization fails (future versions should return a custom error instead).
pub fn analyze_program(
    file_id: String,
    pdb_file_id: Option<String>,
    client: &Client,
    api_key: &str,
) -> Result<AnalysisResult, reqwest::Error> {
    let mut query_params = HashMap::new();
    query_params.insert("fileId", file_id);
    if let Some(pdb_id) = pdb_file_id {
        query_params.insert("pdbFileId", pdb_id);
    }

    let response = client
        .put(ANALYZE_EP)
        .header("Authorization", format!("ApiKey {}", api_key))
        .query(&query_params)
        .send()?
        .error_for_status()?;

    let result_bytes = response.bytes()?;
    let analysis_result: AnalysisResult =
        serde_json::from_slice(&result_bytes).expect("Failed to deserialize analysis result");

    Ok(analysis_result)
}

/// Starts the obfuscation process for a given file using the provided configuration.
///
/// # Arguments
///
/// * `uuid` - UUID of the uploaded binary file (not the PDB).
/// * `config` - Obfuscation configuration as a `CDConfig`.
/// * `client` - A preconfigured `reqwest::blocking::Client`.
/// * `api_key` - Your CodeDefender API key.
///
/// # Returns
///
/// A `Result<String, reqwest::Error>` containing the `execution_id` used for polling.
///
/// # Errors
///
/// Returns an error if the request fails or the server returns a non-success status.
pub fn defend(
    uuid: String,
    config: Config,
    client: &Client,
    api_key: &str,
) -> Result<String, reqwest::Error> {
    let body = serde_json::to_string(&config).expect("Failed to serialize CDConfig");
    let mut query_params = HashMap::new();
    query_params.insert("fileId", uuid);

    let response = client
        .post(DEFEND_EP)
        .header("Authorization", format!("ApiKey {}", api_key))
        .header("Content-Type", "application/json")
        .query(&query_params)
        .body(body)
        .send()?
        .error_for_status()?;

    response.text()
}

/// Polls the obfuscation status or retrieves the obfuscated file.
///
/// This endpoint should be called every 500 milliseconds until the obfuscation is complete.
///
/// ⚠️ Note: This endpoint is rate-limited to **200 requests per minute**.
///
/// # Arguments
///
/// * `uuid` - The execution ID returned by [`defend`].
/// * `client` - A preconfigured `reqwest::blocking::Client`.
/// * `api_key` - Your CodeDefender API key.
///
/// # Returns
///
/// A [`DownloadStatus`] enum indicating whether the file is ready, still processing, or failed.
pub fn download(uuid: String, client: &Client, api_key: &str) -> DownloadStatus {
    let mut query_params = HashMap::new();
    query_params.insert("executionId", uuid);

    let response = client
        .get(DOWNLOAD_EP)
        .header("Authorization", format!("ApiKey {}", api_key))
        .query(&query_params)
        .send();

    match response {
        Ok(resp) => match resp.error_for_status() {
            Ok(resp) => {
                if resp.status() == StatusCode::ACCEPTED {
                    DownloadStatus::Processing
                } else {
                    match resp.bytes() {
                        Ok(bytes) => DownloadStatus::Ready(bytes.to_vec()),
                        Err(e) => DownloadStatus::Failed(e),
                    }
                }
            }
            Err(e) => DownloadStatus::Failed(e),
        },
        Err(e) => DownloadStatus::Failed(e),
    }
}