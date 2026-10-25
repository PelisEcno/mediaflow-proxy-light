// src/extractors/upnshare.rs
use async_trait::async_trait;
use std::collections::HashMap;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use serde_json::Value;

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// KEY = "kiemtienmua911ca" (16 bytes, AES-128)
const AES_KEY: &[u8; 16] = b"kiemtienmua911ca";
// IV  = "1234567890oiuytr"  (16 bytes)
const AES_IV: &[u8; 16] = b"1234567890oiuytr";

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

pub struct UpnshareExtractor(pub BaseExtractor);

impl UpnshareExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

// ════════════════════════════════════════════════
//  HELPERS DE CIFRADO / PARSING
// ════════════════════════════════════════════════

/// Descifra AES-128-CBC + PKCS7.
fn decrypt_aes_cbc(cipher: &[u8]) -> Result<String, ExtractorError> {
    if cipher.is_empty() {
        return Err(ExtractorError::extract("cipher vacío"));
    }
    if cipher.len() % 16 != 0 {
        return Err(ExtractorError::extract(format!(
            "cipher length {} no es múltiplo de 16",
            cipher.len()
        )));
    }

    let mut buf = cipher.to_vec();
    let cipher_obj = Aes128CbcDec::new(AES_KEY.into(), AES_IV.into());
    let plain = cipher_obj
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| ExtractorError::extract(format!("AES-CBC decrypt: {:?}", e)))?;

    String::from_utf8(plain.to_vec())
        .map_err(|e| ExtractorError::extract(format!("utf8 decode: {e}")))
}

/// Detecta si `body` es hex-ascii (con o sin whitespace), JSON plano o binario.
/// Descifra en el caso hex/binario; devuelve el texto tal cual si ya es JSON/HTML.
fn decrypt_body(body: &[u8]) -> Result<String, ExtractorError> {
    // 1) Intentar interpretar como string
    if let Ok(s) = std::str::from_utf8(body) {
        let trimmed = s.trim_start();

        // JSON/HTML plano → no descifrar
        if trimmed.starts_with('{')
            || trimmed.starts_with('[')
            || trimmed.starts_with('<')
        {
            return Ok(s.to_string());
        }

        // Hex puro de longitud par → decodificar y descifrar
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if !cleaned.is_empty()
            && cleaned.len() % 2 == 0
            && cleaned.chars().all(|c| c.is_ascii_hexdigit())
        {
            let cipher_bytes = hex::decode(&cleaned)
                .map_err(|e| ExtractorError::extract(format!("hex decode: {e}")))?;
            return decrypt_aes_cbc(&cipher_bytes);
        }
    }

    // 2) Fallback: binario crudo
    decrypt_aes_cbc(body)
}

/// Convierte `https:\/\/foo` → `https://foo`.
fn unescape_slashes(s: &str) -> String {
    s.replace("\\/", "/")
}

// ════════════════════════════════════════════════
//  EXTRACTOR IMPL
// ════════════════════════════════════════════════

#[async_trait]
impl Extractor for UpnshareExtractor {
    fn host_name(&self) -> &'static str {
        "Upnshare"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        // ----------------------------------------------------------------
        // 1) Parsear el embed: obtener base_url + video_id
        //    Acepta: /#onaha1, /e/onaha1, /embed/onaha1,
        //            /api/v1/info?id=onaha1
        // ----------------------------------------------------------------
        let parsed = url::Url::parse(url)
            .map_err(|e| ExtractorError::extract(format!("invalid URL: {e}")))?;

        let base_url = format!(
            "{}://{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or("")
        );
        let host = parsed.host_str().unwrap_or("").to_string();

        let video_id = {
            // a) ?id=XXXX
            let from_query = parsed.query().and_then(|q| {
                q.split('&')
                    .find_map(|p| p.strip_prefix("id=").map(str::to_string))
            });
            // b) #XXXX
            let from_fragment = parsed
                .fragment()
                .map(|f| f.trim_start_matches('/').to_string())
                .filter(|f| !f.is_empty());
            // c) último segmento del path
            let from_path = parsed
                .path_segments()
                .and_then(|mut segs| segs.next_back())
                .map(str::to_string)
                .filter(|s| {
                    !s.is_empty()
                        && !s.eq_ignore_ascii_case("e")
                        && !s.eq_ignore_ascii_case("embed")
                        && !s.eq_ignore_ascii_case("v")
                        && s != "api"
                        && s != "v1"
                        && s != "info"
                });

            from_query.or(from_fragment).or(from_path)
                .ok_or_else(|| ExtractorError::extract("no video ID"))?
        };

        let referer = format!("{}/", base_url.trim_end_matches('/'));

        let mut req_headers = HashMap::new();
        req_headers.insert("referer".into(), referer.clone());
        req_headers.insert("origin".into(), base_url.clone());
        req_headers.insert("user-agent".into(), USER_AGENT.into());
        req_headers.insert("accept".into(), "*/*".into());

        // ----------------------------------------------------------------
        // 2) GET /api/v1/info?id=<video_id>  →  descifrar  →  JSON
        // ----------------------------------------------------------------
        let info_url = format!(
            "{}/api/v1/info?id={}",
            base_url.trim_end_matches('/'),
            video_id
        );
        let (info_bytes, _) = self
            .0
            .get_bytes(&info_url, Some(req_headers.clone()))
            .await?;
        let info_text = decrypt_body(&info_bytes)?;
        let info_json: Value = serde_json::from_str(&info_text)
            .map_err(|e| ExtractorError::extract(format!("info parse: {e}")))?;

        // (playerId no lo usamos para /video; solo por si se necesita en logs)
        let _player_id = info_json
            .get("playerId")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // ----------------------------------------------------------------
        // 3) GET /api/v1/video?id=<video_id>&w=&h=&r=<host>
        //    →  descifrar  →  JSON  →  cfNative / source / hlsVideoTiktok
        // ----------------------------------------------------------------
        let video_url = format!(
            "{}/api/v1/video?id={}&w=1536&h=864&r={}",
            base_url.trim_end_matches('/'),
            video_id,
            host
        );
        let (video_bytes, _) = self
            .0
            .get_bytes(&video_url, Some(req_headers.clone()))
            .await?;
        let video_text = decrypt_body(&video_bytes)?;
        let video_json: Value = serde_json::from_str(&video_text)
            .map_err(|e| ExtractorError::extract(format!("video parse: {e}")))?;

        // ----------------------------------------------------------------
        // 4) Elegir URL final: cfNative > source > hlsVideoTiktok
        // ----------------------------------------------------------------
        let mut final_url: Option<String> = None;

        if let Some(u) = video_json.get("cfNative").and_then(|v| v.as_str()) {
            if !u.is_empty() {
                final_url = Some(unescape_slashes(u));
            }
        }
        if final_url.is_none() {
            if let Some(u) = video_json.get("source").and_then(|v| v.as_str()) {
                if !u.is_empty() {
                    final_url = Some(unescape_slashes(u));
                }
            }
        }
        if final_url.is_none() {
            if let Some(u) = video_json.get("hlsVideoTiktok").and_then(|v| v.as_str()) {
                if !u.is_empty() {
                    let abs = if u.starts_with("http") {
                        u.to_string()
                    } else {
                        format!("{}{}", base_url.trim_end_matches('/'), u)
                    };
                    final_url = Some(unescape_slashes(&abs));
                }
            }
        }

        let destination_url = final_url.ok_or_else(|| {
            ExtractorError::extract("no URL de stream en /video (cfNative/source/hlsVideoTiktok)")
        })?;

        // ----------------------------------------------------------------
        // 5) Headers de reproducción
        // ----------------------------------------------------------------
        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".into(), referer);
        result_headers.insert("origin".into(), base_url);
        result_headers.insert("user-agent".into(), USER_AGENT.into());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "hls_manifest_proxy",
        })
    }
}
