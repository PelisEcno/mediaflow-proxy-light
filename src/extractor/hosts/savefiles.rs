use std::str::FromStr;
use async_trait::async_trait;
use std::collections::HashMap;

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

pub struct SavefilesExtractor(pub BaseExtractor);

impl SavefilesExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

#[async_trait]
impl Extractor for SavefilesExtractor {
    fn host_name(&self) -> &'static str {
        "Savefiles"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        // 1. Extraer el file_code (ej: https://savefiles.com/e/2nmpcf06mkxc -> 2nmpcf06mkxc)
        let code = url
            .rsplit('/')
            .next()
            .ok_or_else(|| ExtractorError::extract("no code in URL"))?;

        if code.is_empty() {
            return Err(ExtractorError::extract("empty code"));
        }

        // 2. Preparar el POST form-urlencoded a /dl
        let mut form_data = HashMap::new();
        form_data.insert("op", "embed");
        form_data.insert("file_code", code);
        form_data.insert("auto", "1");
        form_data.insert("referer", "https://savefiles.com/");

        let mut req_headers = HashMap::new();
        req_headers.insert("referer".to_string(), url.to_string());
        req_headers.insert("origin".to_string(), "https://savefiles.com".to_string());

        // Construir la petición con reqwest
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
            .post("https://savefiles.com/dl")
            .headers(hm)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(ExtractorError::Http {
                status,
                message: format!("HTTP {status} from /dl"),
            });
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        // 3. Buscar la URL del .m3u8 con una regex simple
        // La línea es: sources: [{file:"https://..."}]
        let re = regex::Regex::new(r#"sources:\s*\[\{file:"([^"]+)"\}\]"#)
            .map_err(|e| ExtractorError::extract(format!("regex failed: {e}")))?;

        let destination_url = re
            .captures(&text)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| ExtractorError::extract("no m3u8 URL found in response"))?;

        // 4. Devolver el resultado (es un HLS)
        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".to_string(), "https://savefiles.com/".to_string());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "hls_manifest_proxy",
        })
    }
}
