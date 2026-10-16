use async_trait::async_trait;
use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

pub struct FileMoonExtractor(pub BaseExtractor);

impl FileMoonExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

/// Decode a base64 string (URL-safe or standard) with auto-padding.
fn base64_decode_flexible(input: &str) -> Result<Vec<u8>, ExtractorError> {
    // Limpiar: solo caracteres base64 válidos
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(*c))
        .collect();

    if cleaned.is_empty() {
        return Err(ExtractorError::extract("base64 input vacío"));
    }

    // Normalizar URL-safe a standard
    let normalized = cleaned.replace('-', "+").replace('_', "/");

    // Añadir padding
    let trimmed = normalized.trim_end_matches('=');
    let needed = (4 - trimmed.len() % 4) % 4;
    let padded = format!("{}{}", trimmed, "=".repeat(needed));

    STANDARD
        .decode(&padded)
        .map_err(|e| ExtractorError::extract(format!("base64 decode failed: {e}")))
}

/// Mapa version → [índice1, índice2]
/// version 1 → [1, 30]
/// version 2 → [2, 29]
/// ...
/// version 16 → [16, 15]
fn get_version_indices(version: &str) -> Option<(usize, usize)> {
    let n: usize = version.parse().ok()?;
    if n < 1 || n > 20 {
        return None;
    }
    Some((n, 31 - n))
}

/// Selecciona los key_parts según la version.
fn select_key_parts(
    key_parts: &[serde_json::Value],
    version: &str,
) -> Vec<String> {
    let all_parts: Vec<String> = key_parts
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    if let Some((idx1, idx2)) = get_version_indices(version) {
        // Convertir a base 0
        let i1 = idx1.saturating_sub(1);
        let i2 = idx2.saturating_sub(1);

        if i1 < all_parts.len() && i2 < all_parts.len() {
            return vec![all_parts[i1].clone(), all_parts[i2].clone()];
        }
    }

    // Fallback: usar todos
    all_parts
}

/// Combina los key_parts seleccionados en un solo Vec<u8>.
fn combine_key_parts(parts: &[String]) -> Result<Vec<u8>, ExtractorError> {
    let mut combined = Vec::new();
    for part in parts {
        combined.extend(base64_decode_flexible(part)?);
    }
    Ok(combined)
}

/// Decrypt AES-256-GCM.
fn decrypt_playback(playback: &serde_json::Value) -> Result<serde_json::Value, ExtractorError> {
    let key_parts_raw = playback["key_parts"]
        .as_array()
        .ok_or_else(|| ExtractorError::extract("playback.key_parts missing"))?;

    let version = playback["version"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let selected = select_key_parts(key_parts_raw, &version);
    let key_bytes_full = combine_key_parts(&selected)?;

    if key_bytes_full.len() < 32 {
        return Err(ExtractorError::extract(format!(
            "key demasiado corta: {} bytes (mínimo 32)",
            key_bytes_full.len()
        )));
    }

    // Usar solo los primeros 32 bytes
    let key_bytes = &key_bytes_full[..32];

    let iv_str = playback["iv"]
        .as_str()
        .ok_or_else(|| ExtractorError::extract("playback.iv missing"))?;
    let iv_bytes = base64_decode_flexible(iv_str)?;

    if iv_bytes.len() != 12 {
        return Err(ExtractorError::extract(format!(
            "IV inválido: {} bytes (esperado 12)",
            iv_bytes.len()
        )));
    }

    let payload_str = playback["payload"]
        .as_str()
        .ok_or_else(|| ExtractorError::extract("playback.payload missing"))?;
    let payload_bytes = base64_decode_flexible(payload_str)?;

    if payload_bytes.len() < 16 {
        return Err(ExtractorError::extract(format!(
            "payload demasiado corto: {} bytes",
            payload_bytes.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| ExtractorError::extract(format!("AES key init failed: {e}")))?;

    let nonce = Nonce::from_slice(&iv_bytes);

    let plaintext = cipher
        .decrypt(nonce, payload_bytes.as_ref())
        .map_err(|_| ExtractorError::extract("AES-256-GCM decryption failed"))?;

    let json: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| ExtractorError::extract(format!("JSON parse failed: {e}")))?;

    Ok(json)
}

#[async_trait]
impl Extractor for FileMoonExtractor {
    fn host_name(&self) -> &'static str {
        "FileMoon"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| ExtractorError::extract(format!("invalid URL: {e}")))?;

        let path = parsed.path().trim_end_matches('/');
        let code = path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty() && *s != "e" && *s != "d")
            .ok_or_else(|| {
                ExtractorError::extract(format!("no video code in URL: {url}"))
            })?;

        let scheme = parsed.scheme();
        let host = parsed.host_str().ok_or_else(|| {
            ExtractorError::extract("URL has no host")
        })?;
        let api_url = format!("{scheme}://{host}/api/videos/{code}");

        let mut req_headers = HashMap::new();
        req_headers.insert("referer".to_string(), url.to_string());

        let (text, _) = self.0.get_text(&api_url, Some(req_headers)).await?;

        let data: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ExtractorError::extract(format!("API JSON parse failed: {e}")))?;

        if let Some(err_msg) = data.get("error") {
            return Err(ExtractorError::extract(format!("API error: {err_msg}")));
        }

        let playback = data.get("playback").ok_or_else(|| {
            ExtractorError::extract("no playback field")
        })?;

        let decrypted = decrypt_playback(playback)?;

        let sources = decrypted["sources"]
            .as_array()
            .ok_or_else(|| ExtractorError::extract("no sources"))?;

        let hls_source = sources
            .iter()
            .find(|s| {
                s["mime_type"].as_str() == Some("application/vnd.apple.mpegurl")
                    || s["url"]
                        .as_str()
                        .map(|u| u.contains(".m3u8"))
                        .unwrap_or(false)
            })
            .ok_or_else(|| ExtractorError::extract("no HLS source"))?;

        let destination_url = hls_source["url"]
            .as_str()
            .ok_or_else(|| ExtractorError::extract("HLS source has no url"))?
            .to_string();

        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".to_string(), url.to_string());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "hls_manifest_proxy",
        })
    }
}
