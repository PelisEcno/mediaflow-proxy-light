use std::str::FromStr;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::HashMap;

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

pub struct HexloadExtractor(pub BaseExtractor);

impl HexloadExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

#[async_trait]
impl Extractor for HexloadExtractor {
    fn host_name(&self) -> &'static str {
        "Hexload"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        // 1. Extraer el ID del embed (ej: https://hexload.com/embed-b6v7uku7pxli -> b6v7uku7pxli)
        let id = url
            .rsplit('/')
            .next()
            .ok_or_else(|| ExtractorError::extract("no id in URL"))?
            .trim_start_matches("embed-");

        if id.is_empty() {
            return Err(ExtractorError::extract("empty id"));
        }

        // 2. Preparar el POST form-urlencoded a /download
        let mut form_data = HashMap::new();
        form_data.insert("op", "download3");
        form_data.insert("id", id);
        form_data.insert("ajax", "1");
        form_data.insert("method_free", "1");

        let mut req_headers = HashMap::new();
        req_headers.insert("referer".to_string(), url.to_string());
        req_headers.insert("origin".to_string(), "https://hexload.com".to_string());

        // Construir la petición con reqwest (usando el cliente del BaseExtractor)
        let mut hm = reqwest::header::HeaderMap::new();
        let mut merged = self.0.base_headers.clone();
        merged.extend(req_headers);
        for (k, v) in &merged {
            if let (Ok(n), Ok(val)) = (
                reqwest::header::HeaderName::from_str(k),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                hm.insert(n, val);
            }
        }

        let resp = self
            .0
            .client
            .post("https://hexload.com/download")
            .headers(hm)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(ExtractorError::Http {
                status,
                message: format!("HTTP {status} from /download"),
            });
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        // 3. Parsear el JSON y extraer result.url
        let data: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ExtractorError::extract(format!("JSON parse failed: {e}")))?;

        if data["msg"].as_str() != Some("OK") {
            return Err(ExtractorError::extract(format!(
                "Server error: {}",
                data["msg"]
            )));
        }

        let raw_url = data["result"]["url"]
            .as_str()
            .ok_or_else(|| ExtractorError::extract("no result.url"))?;

        // 4. Codificar a Base64
        let base64_url = STANDARD.encode(raw_url);

        // 5. Construir la URL final (test.pl?op=...)
        let destination_url = format!("https://hexload.com/cgi-bin/test.pl?op={}", base64_url);

        // 6. Devolver el resultado (es un .mp4 directo)
        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".to_string(), "https://hexload.com/".to_string());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "proxy_stream_endpoint", // .mp4 directo
        })
    }
}
