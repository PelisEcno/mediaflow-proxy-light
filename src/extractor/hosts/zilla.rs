use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

fn hash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"/play/([a-f0-9]{32})").unwrap())
}

pub struct ZillaExtractor {
    pub base: BaseExtractor,
}

impl ZillaExtractor {
    pub fn new(request_headers: std::collections::HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self {
            base: BaseExtractor::new(request_headers, proxy_url),
        }
    }
}

#[async_trait]
impl Extractor for ZillaExtractor {
    fn host_name(&self) -> &'static str {
        "Zilla"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        // Extraer el hash de la URL
        let hash = hash_re()
            .captures(url)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| ExtractorError::extract("Zilla: could not extract hash from URL"))?;

        // Construir la URL del m3u8
        let video_url = format!("https://player.zilla-networks.com/m3u8/{}", hash);

        // Headers: Referer al player y User-Agent de navegador
        let mut headers = self.base.base_headers.clone();
        headers.insert(
            "referer".to_string(),
            "https://player.zilla-networks.com/".to_string(),
        );
        headers.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                .to_string(),
        );

        Ok(ExtractorResult {
            destination_url: video_url,
            request_headers: headers,
            mediaflow_endpoint: "hls_manifest_proxy",
        })
    }
}
