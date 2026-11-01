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

        // 5. Construir la URL del test.pl (que redirige al .mp4)
        let test_url = format!("https://hexload.com/cgi-bin/test.pl?op={}", base64_url);

        // 6. Hacer la petición GET a test.pl SIN seguir redirecciones (solo queremos el Location)
        let mut redirect_headers = HashMap::new();
        redirect_headers.insert("referer".to_string(), "https://hexload.com/".to_string());

        let mut hm2 = reqwest::header::HeaderMap::new();
        let mut merged2 = self.0.base_headers.clone();
        merged2.extend(redirect_headers);
        for (k, v) in &merged2 {
            if let (Ok(n), Ok(val)) = (
                reqwest::header::HeaderName::from_str(k),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                hm2.insert(n, val);
            }
        }

        // Nota: reqwest por defecto sigue redirecciones. Para evitarlo, usamos una petición
        // con un cliente configurado a no seguirlas, o simplemente leemos el header Location.
        // Como el cliente del BaseExtractor sigue redirecciones por defecto, hacemos la petición
        // y leemos la URL final (resp.url()).
        let resp_redirect = self
            .0
            .client
            .get(&test_url)
            .headers(hm2)
            .send()
            .await
            .map_err(|e| ExtractorError::Network(e.to_string()))?;

        // La URL final (después de redirecciones) es el .mp4 real
        let destination_url = resp_redirect.url().to_string();

        // 7. Devolver el resultado (es un .mp4 directo)
        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".to_string(), "https://hexload.com/".to_string());

        Ok(ExtractorResult {
            destination_url,
            request_headers: result_headers,
            mediaflow_endpoint: "proxy_stream_endpoint",
        })
    }
}
