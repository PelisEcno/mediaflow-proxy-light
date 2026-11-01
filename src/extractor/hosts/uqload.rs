use async_trait::async_trait;
use regex::Regex;
use rquest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::extractor::base::{
    build_chrome_client, BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};
use crate::extractor::packed;

fn sources_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)sources\s*:\s*\[\s*\{\s*file\s*:\s*["']([^"']+)["']"#).unwrap()
    })
}

fn fallback_media_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"["'](https?://[^"']+\.(?:m3u8|mp4)[^"']*)["']"#).unwrap()
    })
}

pub struct UqloadExtractor {
    pub base: BaseExtractor,
    chrome_client: rquest::Client,
}

impl UqloadExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        let chrome_client = build_chrome_client(proxy_url.as_deref());
        Self {
            base: BaseExtractor::new(request_headers, proxy_url),
            chrome_client,
        }
    }
}

#[async_trait]
impl Extractor for UqloadExtractor {
    fn host_name(&self) -> &'static str {
        "Uqload"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        let ua = self
            .base
            .base_headers
            .get("user-agent")
            .cloned()
            .unwrap_or_else(|| {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
                    .to_string()
            });

        let mut hm = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&ua) {
            hm.insert(HeaderName::from_static("user-agent"), v);
        }
        // Uqload requiere Referer del propio embed
        if let Ok(v) = HeaderValue::from_str(url) {
            hm.insert(HeaderName::from_static("referer"), v);
        }

        let resp = self
            .chrome_client
            .get(url)
            .headers(hm)
            .send()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(ExtractorError::Http {
                status,
                message: format!("HTTP {status} from {url}"),
            });
        }

        let final_url = resp.url().to_string();
        let html = resp
            .text()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        // ---- Desempacar P.A.C.K.E.R. si aplica ----
        let js = if packed::is_packed(&html) {
            packed::unpack_packed_js(&html)
                .ok_or_else(|| ExtractorError::extract("Uqload: packed unpack failed"))?
        } else {
            html
        };

        // 1) sources: [{file:"..."}]
        let mut video_url = sources_re()
            .captures(&js)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        // 2) Fallback: cualquier .m3u8/.mp4 suelto
        if video_url.is_none() {
            video_url = fallback_media_re()
                .captures(&js)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());
        }

        let video_url =
            video_url.ok_or_else(|| ExtractorError::extract("Uqload: video URL not found"))?;

        // Endpoint según tipo de media (.m3u8 → HLS, .mp4 → stream)
        let endpoint = if video_url.contains(".m3u8") {
            "hls_manifest_proxy"
        } else {
            "proxy_stream_endpoint"
        };

        // Referer: origen final (por si hubo redirect)
        let origin = final_url.split('/').take(3).collect::<Vec<_>>().join("/");
        let mut headers = self.base.base_headers.clone();
        headers.insert("referer".to_string(), format!("{origin}/"));

        Ok(ExtractorResult {
            destination_url: video_url,
            request_headers: headers,
            mediaflow_endpoint: endpoint,
        })
    }
}
