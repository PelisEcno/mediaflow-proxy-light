use async_trait::async_trait;
use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

pub struct FileMoonExtractor(pub BaseExtractor);

impl FileMoonExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

/// Decode a base64 string trying EVERY possible variant.
/// 
/// FileMoon's key_parts have DIFFERENT lengths (some 32 chars, some 22 chars).
/// Strings with length % 4 == 2 or 3 need padding added.
fn base64url_decode(input: &str) -> Result<Vec<u8>, ExtractorError> {
    // ── Paso 1: Filtrar solo caracteres base64 válidos ────────────────
    let cleaned: String = input
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || *c == '+'
                || *c == '/'
                || *c == '-'
                || *c == '_'
                || *c == '='
        })
        .collect();

    if cleaned.is_empty() {
        return Err(ExtractorError::extract("base64 input has no valid characters"));
    }

    // ── Paso 2: Normalizar a base64 estándar (para STANDARD engine) ────
    let as_standard = cleaned.replace('-', "+").replace('_', "/");

    // ── Paso 3: Añadir padding si falta ───────────────────────────────
    // base64 requiere longitud múltiplo de 4.
    // Añadimos '=' hasta que sea múltiplo de 4.
    let add_padding = |s: &str| -> String {
        let trimmed = s.trim_end_matches('=');
        let needed = (4 - trimmed.len() % 4) % 4;
        format!("{}{}", trimmed, "=".repeat(needed))
    };

    let standard_padded = add_padding(&as_standard);
    let urlsafe_padded = add_padding(&cleaned);

    // ── Paso 4: Intentar TODAS las variantes ──────────────────────────
    let mut first_error = String::from("no attempts made");

    // Intento 1: STANDARD con padding
    match STANDARD.decode(&standard_padded) {
        Ok(bytes) => return Ok(bytes),
        Err(e) => first_error = format!("standard_padded: {e}"),
    }

    // Intento 2: STANDARD sin padding (por si acaso)
    match STANDARD_NO_PAD.decode(as_standard.trim_end_matches('=')) {
        Ok(bytes) => return Ok(bytes),
        Err(_) => {}
    }

    // Intento 3: URL_SAFE con padding
    match URL_SAFE.decode(&urlsafe_padded) {
        Ok(bytes) => return Ok(bytes),
        Err(_) => {}
    }

    // Intento 4: URL_SAFE sin padding
    match URL_SAFE_NO_PAD.decode(cleaned.trim_end_matches('=')) {
        Ok(bytes) => return Ok(bytes),
        Err(_) => {}
    }

    // ── Paso 5: Todo falló ────────────────────────────────────────────
    Err(ExtractorError::extract(format!(
        "base64 decode failed (4 engines). First error: {}. Input length: {}, Input: {}",
        first_error,
        cleaned.len(),
        &cleaned[..cleaned.len().min(80)]
    )))
}
/// Concatenate all key_parts (each base64-decoded) into a single byte vector.
fn combine_key_parts(key_parts: &[serde_json::Value]) -> Result<Vec<u8>, ExtractorError> {
    let mut combined = Vec::new();
    for part in key_parts {
        let s = part
            .as_str()
            .ok_or_else(|| ExtractorError::extract("key_part is not a string"))?;
        combined.extend(base64url_decode(s)?);
    }
    Ok(combined)
}

/// Decrypt the `playback` object using AES-256-GCM.
fn decrypt_playback(playback: &serde_json::Value) -> Result<serde_json::Value, ExtractorError> {
    let key_parts = playback["key_parts"]
        .as_array()
        .ok_or_else(|| ExtractorError::extract("playback.key_parts missing or not an array"))?;

    let key_bytes = combine_key_parts(key_parts)?;

    // Validar tamaño de la clave (debe ser 32 bytes para AES-256)
    if key_bytes.len() != 32 {
        return Err(ExtractorError::extract(format!(
            "AES-256 key length is {} bytes, expected 32. Key parts: {}",
            key_bytes.len(),
            key_parts.len()
        )));
    }

    let iv_str = playback["iv"]
        .as_str()
        .ok_or_else(|| ExtractorError::extract("playback.iv missing"))?;
    let iv_bytes = base64url_decode(iv_str)?;

    if iv_bytes.len() != 12 {
        return Err(ExtractorError::extract(format!(
            "unexpected IV length: {} (expected 12)",
            iv_bytes.len()
        )));
    }

    let payload_str = playback["payload"]
        .as_str()
        .ok_or_else(|| ExtractorError::extract("playback.payload missing"))?;
    let payload_bytes = base64url_decode(payload_str)?;

    // AES-GCM requiere al menos 16 bytes (tag de autenticación)
    if payload_bytes.len() < 16 {
        return Err(ExtractorError::extract(format!(
            "payload too short: {} bytes (minimum 16 for AES-GCM tag)",
            payload_bytes.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| ExtractorError::extract(format!("AES-256-GCM key init failed: {e}")))?;

    let nonce = Nonce::from_slice(&iv_bytes);

    let plaintext = cipher
        .decrypt(nonce, payload_bytes.as_ref())
        .map_err(|_| ExtractorError::extract("AES-256-GCM decryption failed (bad key, IV, or tampered payload)"))?;

    let json: serde_json::Value = serde_json::from_slice(&plaintext).map_err(|e| {
        ExtractorError::extract(format!("JSON parse of decrypted payload failed: {e}"))
    })?;

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
        // ── 1. Parse video code del URL ───────────────────────────────
        let parsed = url::Url::parse(url)
            .map_err(|e| ExtractorError::extract(format!("invalid URL: {e}")))?;

        let path = parsed.path().trim_end_matches('/');
        let code = path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty() && *s != "e" && *s != "d")
            .ok_or_else(|| {
                ExtractorError::extract(format!("could not extract video code from URL: {url}"))
            })?;

        // ── 2. Llamar al API endpoint ────────────────────────────────
        let scheme = parsed.scheme();
        let host = parsed
            .host_str()
            .ok_or_else(|| ExtractorError::extract("URL has no host"))?;
        let api_url = format!("{scheme}://{host}/api/videos/{code}");

        let mut req_headers = HashMap::new();
        req_headers.insert("referer".to_string(), url.to_string());

        let (text, _final_url) = self.0.get_text(&api_url, Some(req_headers)).await?;

        // ── 3. Parse JSON response ───────────────────────────────────
        let data: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ExtractorError::extract(format!("FileMoon API JSON parse failed: {e}")))?;

        if let Some(err_msg) = data.get("error") {
            return Err(ExtractorError::extract(format!(
                "FileMoon API error: {err_msg}"
            )));
        }

        let playback = data.get("playback").ok_or_else(|| {
            ExtractorError::extract("FileMoon: no playback field in API response")
        })?;

        if playback.get("key_parts").is_none() || playback.get("payload").is_none() {
            return Err(ExtractorError::extract(
                "FileMoon: playback data is incomplete (missing key_parts or payload)",
            ));
        }

        // ── 4. Decrypt playback ──────────────────────────────────────
        let decrypted = decrypt_playback(playback)?;

        // ── 5. Encontrar HLS source ──────────────────────────────────
        let sources = decrypted["sources"]
            .as_array()
            .ok_or_else(|| ExtractorError::extract("FileMoon: decrypted payload has no sources"))?;

        // Buscar HLS (mime_type application/vnd.apple.mpegurl o .m3u8 en URL)
        let hls_source = sources
            .iter()
            .find(|s| {
                s["mime_type"].as_str() == Some("application/vnd.apple.mpegurl")
                    || s["url"]
                        .as_str()
                        .map(|u| u.contains(".m3u8"))
                        .unwrap_or(false)
            })
            .ok_or_else(|| {
                ExtractorError::extract("FileMoon: no HLS source found in decrypted playback")
            })?;

        let destination_url = hls_source["url"]
            .as_str()
            .ok_or_else(|| ExtractorError::extract("FileMoon: HLS source has no url field"))?
            .to_string();

        // ── 6. Return result ─────────────────────────────────────────
        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".to_string(), url.to_string());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "hls_manifest_proxy",
        })
    }
}
