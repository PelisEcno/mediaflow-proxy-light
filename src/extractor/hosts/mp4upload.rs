use async_trait::async_trait;
use std::collections::HashMap;

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

pub struct MP4UploadExtractor(pub BaseExtractor);

impl MP4UploadExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

#[async_trait]
impl Extractor for MP4UploadExtractor {
    fn host_name(&self) -> &'static str { "MP4Upload" }

    async fn extract(&self, url: &str, _extra: &ExtraParams) -> Result<ExtractorResult, ExtractorError> {
        // 1. Hacer petición al embed
        let mut req_headers = HashMap::new();
        req_headers.insert("referer".into(), "https://www.mp4upload.com/".into());
        req_headers.insert("user-agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into());
        
        let (html, _) = self.0.get_text(url, Some(req_headers.clone())).await?;

        // 2. Buscar la URL del .mp4
        let mp4_regex = regex::Regex::new(r#"src:\s*"(https?://[^"]+\.mp4[^"]*)""#)
            .map_err(|e| ExtractorError::extract(format!("regex error: {e}")))?;

        let destination_url = mp4_regex.find(&html)
            .map(|m| m.as_str().replace("src: ", "").replace("\"", ""))
            .ok_or_else(|| ExtractorError::extract("no mp4 URL found"))?;

        // 3. Headers mínimos para que el reproductor no de 403
        let mut result_headers = HashMap::new();
        result_headers.insert("referer".into(), "https://www.mp4upload.com/".into());
        result_headers.insert("user-agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "hls_manifest_proxy", // o el que uses para MP4
        })
    }
}
