use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

const REFERER: &str = "https://www.yourupload.com/";

/// `<meta property="og:video" content="https://vidcache.net:8161/…/video.mp4">`
fn og_video_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"<meta\s+property=["']og:video["']\s+content=["'](https?://[^"']+)["']"#)
            .unwrap()
    })
}

/// `jwplayerOptions = { file: 'https://vidcache.net:8161/…/video.mp4', … }`
fn jw_file_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"file:\s*['"](https?://[^'"]+\.mp4[^'"]*)['"]"#).unwrap())
}

/// Finds the direct `.mp4` URL in the HTML of a YourUpload embed page.
///
/// The page carries it twice: in the `og:video` meta tag and as the `file` of the JW Player
/// options. The meta tag is tried first; the player option is the fallback.
pub fn parse_video_url(html: &str) -> Option<String> {
    og_video_re()
        .captures(html)
        .or_else(|| jw_file_re().captures(html))
        .map(|c| c[1].replace("&amp;", "&"))
}

pub struct YourUploadExtractor(pub BaseExtractor);

impl YourUploadExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

#[async_trait]
impl Extractor for YourUploadExtractor {
    fn host_name(&self) -> &'static str {
        "YourUpload"
    }

    async fn extract(
        &self,
        url: &str,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        let mut h = HashMap::new();
        h.insert("referer".to_string(), REFERER.to_string());

        let (html, _) = self.0.get_text(url, Some(h)).await?;

        let destination_url = parse_video_url(&html)
            .ok_or_else(|| ExtractorError::extract("YourUpload: mp4 URL not found"))?;

        // The .mp4 host answers 500 without a YourUpload Referer, and 302-redirects to the real
        // file server once it has one; the stream proxy follows that redirect.
        let mut headers = self.0.base_headers.clone();
        headers.insert("referer".to_string(), REFERER.to_string());

        Ok(ExtractorResult {
            destination_url,
            request_headers: headers,
            mediaflow_endpoint: "proxy_stream_endpoint",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed from a real embed page.
    const PAGE: &str = r#"<!DOCTYPE html><html lang="eng"><head><title>Episode_6.mp4</title>
<meta property="og:image" content="https://vidcache.net:8161/static/abc/preview.jpeg">
<meta property="og:video" content="https://vidcache.net:8161/a20261102a01IM8k4lpj/video.mp4">
<link rel="stylesheet" type="text/css" href="https://bowercdn.net/c/normalize.css"></head>
<body><script>jwplayer.key = 'x'; var jwplayerOptions = { file: 'https://vidcache.net:8161/a20261102a01IM8k4lpj/video.mp4',
 image: 'https://vidcache.net:8161/static/abc/preview.jpeg', width: '100%' };</script></body></html>"#;

    #[test]
    fn reads_og_video() {
        assert_eq!(
            parse_video_url(PAGE).as_deref(),
            Some("https://vidcache.net:8161/a20261102a01IM8k4lpj/video.mp4")
        );
    }

    #[test]
    fn falls_back_to_the_player_file() {
        let page = PAGE.replace(r#"<meta property="og:video""#, r#"<meta property="og:other""#);
        assert_eq!(
            parse_video_url(&page).as_deref(),
            Some("https://vidcache.net:8161/a20261102a01IM8k4lpj/video.mp4")
        );
    }

    #[test]
    fn decodes_html_entities_in_the_url() {
        let page = r#"<meta property="og:video" content="https://h.net/v.mp4?a=1&amp;b=2">"#;
        assert_eq!(parse_video_url(page).as_deref(), Some("https://h.net/v.mp4?a=1&b=2"));
    }

    #[test]
    fn none_when_the_page_has_no_video() {
        assert_eq!(parse_video_url("<html><body>File not found</body></html>"), None);
    }
}
