use async_trait::async_trait;
use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core::OsRng;
use serde_json::{json, Value};

use crate::extractor::base::{
    BaseExtractor, ExtraParams, Extractor, ExtractorError, ExtractorResult,
};

pub struct ByseExtractor(pub BaseExtractor);

impl ByseExtractor {
    pub fn new(request_headers: HashMap<String, String>, proxy_url: Option<String>) -> Self {
        Self(BaseExtractor::new(request_headers, proxy_url))
    }
}

// ════════════════════════════════════════════════
//  POW ALGORITHM
// ════════════════════════════════════════════════
const BE: usize = 512;
const LT: usize = BE - 1;
const DR: usize = 2;
const LR: u32 = 2654435761;
const HR: u32 = 2246822519;

fn rotl(x: u32, n: u32) -> u32 { x.rotate_left(n) }

fn ye(t: &mut [u32; 4]) {
    t[0] = t[0].wrapping_add(t[1]);
    t[3] = rotl(t[3] ^ t[0], 16);
    t[2] = t[2].wrapping_add(t[3]);
    t[1] = rotl(t[1] ^ t[2], 12);
    t[0] = t[0].wrapping_add(t[1]);
    t[3] = rotl(t[3] ^ t[0], 8);
    t[2] = t[2].wrapping_add(t[3]);
    t[1] = rotl(t[1] ^ t[2], 7);
}

fn gr(input: &[u8]) -> [u32; 8] {
    let mut e = [1779033703u32, 3144134277, 1013904242, 2773480762];
    for &b in input {
        e[0] = e[0].wrapping_add(b as u32);
        e[0] = rotl(e[0], 7);
        ye(&mut e);
    }
    for _ in 0..8 { ye(&mut e); }
    let mut r = [0u32; BE];
    for i in 0..BE { ye(&mut e); r[i] = e[0] ^ e[2]; }
    for _ in 0..DR {
        for s in 0..BE {
            let a = (r[s] as usize) & LT;
            let mut c = r[s].wrapping_add(r[a]);
            c = rotl(c, 13);
            c ^= r[(s + 1) & LT].wrapping_mul(LR);
            r[s] = c;
            e[0] ^= c;
            ye(&mut e);
        }
    }
    let mut n = [0u32; 8];
    let o = BE / 8;
    for i in 0..8 {
        ye(&mut e);
        let mut s = e[0];
        let a = i * o;
        for c in 0..o {
            let d = r[a + c];
            s = s.wrapping_add(d);
            s = rotl(s, 5);
            s ^= d.wrapping_mul(HR);
        }
        n[i] = s ^ e[2];
    }
    n
}

fn wr(t: &[u32]) -> u32 {
    let mut e = 0;
    for &n in t {
        if n == 0 { e += 32; continue; }
        e += n.leading_zeros();
        return e;
    }
    e
}

fn solve_pow(nonce: &str, difficulty: u32) -> String {
    let prefix = format!("{}:", nonce);
    let mut solution = 0u64;
    loop {
        let data = format!("{}{}", prefix, solution);
        let hash = gr(data.as_bytes());
        if wr(&hash) >= difficulty { return solution.to_string(); }
        solution += 1;
    }
}

// ════════════════════════════════════════════════
//  AES KEY BUILD
// ════════════════════════════════════════════════

fn decode_jwk_part(part: &str) -> Result<Vec<u8>, ExtractorError> {
    URL_SAFE_NO_PAD.decode(part.trim_end_matches('='))
        .map_err(|e| ExtractorError::extract(format!("jwk decode failed: {e}")))
}

fn build_aes_key(key_parts: &[Value], version: usize) -> Result<Vec<u8>, ExtractorError> {
    if version < 1 || version > 30 {
        return Err(ExtractorError::extract("invalid version"));
    }
    let i1 = version - 1;
    let i2 = 30 - version;
    if i1 >= key_parts.len() || i2 >= key_parts.len() {
        return Err(ExtractorError::extract("key index out of bounds"));
    }
    let part1 = key_parts[i1].as_str().ok_or_else(|| ExtractorError::extract("invalid part 1"))?;
    let part2 = key_parts[i2].as_str().ok_or_else(|| ExtractorError::extract("invalid part 2"))?;
    let mut key = Vec::new();
    key.extend(decode_jwk_part(part1)?);
    key.extend(decode_jwk_part(part2)?);
    if key.len() < 32 {
        return Err(ExtractorError::extract("key too short"));
    }
    Ok(key[..32].to_vec())
}

// ════════════════════════════════════════════════
//  EXTRACTOR IMPL
// ════════════════════════════════════════════════

#[async_trait]
impl Extractor for ByseExtractor {
    fn host_name(&self) -> &'static str { "Byse" }

    async fn extract(&self, url: &str, _extra: &ExtraParams) -> Result<ExtractorResult, ExtractorError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| ExtractorError::extract(format!("invalid URL: {e}")))?;
        let video_id = parsed.path().trim_end_matches('/').rsplit('/').next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ExtractorError::extract("no video ID"))?;

        let base_url = "https://n1mwq.org";
        let referer = url;
        let origin = "https://n1mwq.org";

        let mut req_headers = HashMap::new();
        req_headers.insert("referer".into(), referer.into());
        req_headers.insert("origin".into(), origin.into());
        req_headers.insert("user-agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36".into());

        // 1. CHALLENGE
        let challenge_url = format!("{}/api/videos/access/challenge", base_url);
        let (challenge_text, _) = self.0.get_text(&challenge_url, Some(req_headers.clone())).await?;
        let challenge_json: Value = serde_json::from_str(&challenge_text)
            .map_err(|e| ExtractorError::extract(format!("challenge parse: {e}")))?;
        let challenge_id = challenge_json["challenge_id"].as_str().ok_or_else(|| ExtractorError::extract("no challenge_id"))?;
        let nonce = challenge_json["nonce"].as_str().ok_or_else(|| ExtractorError::extract("no nonce"))?;

        // 2. ATTEST (ECDSA P-256)
        let mut csprng = OsRng;
        let signing_key = SigningKey::random(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(public_key.x().ok_or_else(|| ExtractorError::extract("no x"))?);
        let y = URL_SAFE_NO_PAD.encode(public_key.y().ok_or_else(|| ExtractorError::extract("no y"))?);
        let signature: Signature = signing_key.sign(nonce.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let attest_url = format!("{}/api/videos/access/attest", base_url);
        let attest_body = json!({
            "viewer_id": "AtuauIaIq2YSMIBc-Ull4A",
            "device_id": "fqWjmX5ayBvC_eCFbYqiqw",
            "challenge_id": challenge_id,
            "nonce": nonce,
            "signature": sig_b64,
            "public_key": { "crv": "P-256", "ext": true, "key_ops": ["verify"], "kty": "EC", "x": x, "y": y }
        });
        let (attest_text, _) = self.0.post_json_text(&attest_url, attest_body, Some(req_headers.clone())).await?;
        let attest_json: Value = serde_json::from_str(&attest_text)
            .map_err(|e| ExtractorError::extract(format!("attest parse: {e}")))?;
        let token = attest_json["token"].as_str().ok_or_else(|| ExtractorError::extract("no token"))?;

        // 3. CAPTCHA
        let captcha_url = format!("{}/api/videos/{}/embed/captcha", base_url, video_id);
        let captcha_body = json!({
            "fingerprint": { "token": token, "viewer_id": "AtuauIaIq2YSMIBc-Ull4A", "device_id": "fqWjmX5ayBvC_eCFbYqiqw", "confidence": 0.93 }
        });
        let (captcha_text, _) = self.0.post_json_text(&captcha_url, captcha_body, Some(req_headers.clone())).await?;
        let captcha_json: Value = serde_json::from_str(&captcha_text)
            .map_err(|e| ExtractorError::extract(format!("captcha parse: {e}")))?;
        let pow_token = captcha_json["pow_token"].as_str().ok_or_else(|| ExtractorError::extract("no pow_token"))?;
        let pow_nonce = captcha_json["pow_nonce"].as_str().ok_or_else(|| ExtractorError::extract("no pow_nonce"))?;
        let pow_difficulty = captcha_json["pow_difficulty"].as_u64().unwrap_or(16) as u32;

        // 4. POW
        let solution = solve_pow(pow_nonce, pow_difficulty);

        // 5. VERIFY
        let verify_url = format!("{}/api/videos/{}/embed/captcha/verify", base_url, video_id);
        let verify_body = json!({
            "pow_token": pow_token, "solution": solution,
            "fingerprint": { "token": token, "viewer_id": "AtuauIaIq2YSMIBc-Ull4A", "device_id": "fqWjmX5ayBvC_eCFbYqiqw", "confidence": 0.93 }
        });
        let (verify_text, _) = self.0.post_json_text(&verify_url, verify_body, Some(req_headers.clone())).await?;
        let verify_json: Value = serde_json::from_str(&verify_text)
            .map_err(|e| ExtractorError::extract(format!("verify parse: {e}")))?;
        let captcha_token = verify_json["token"].as_str().ok_or_else(|| ExtractorError::extract("no captcha_token"))?;

                // 6. PLAYBACK
        let playback_url = format!("{}/api/videos/{}/embed/playback", base_url, video_id);
        let playback_body = json!({
            "fingerprint": { 
                "token": token, 
                "viewer_id": "AtuauIaIq2YSMIBc-Ull4A", 
                "device_id": "fqWjmX5ayBvC_eCFbYqiqw", 
                "confidence": 0.93 
            }
        });

        let mut playback_headers = req_headers.clone();
        // 👇 AÑADIR EL TOKEN DEL CAPTCHA
        playback_headers.insert("x-captcha-token".to_string(), captcha_token.to_string());
        // 👇 AÑADIR EL EMBED PARENT (por si acaso)
        playback_headers.insert("x-embed-parent".to_string(), referer.to_string());

        let (playback_text, _) = self.0.post_json_text(&playback_url, playback_body, Some(playback_headers)).await?;
        // 7. DESCIFRAR
        let key_parts = playback["key_parts"].as_array().ok_or_else(|| ExtractorError::extract("no key_parts"))?;
        let version: usize = playback["version"].as_str().unwrap_or("1").parse().map_err(|_| ExtractorError::extract("invalid version"))?;
        let key = build_aes_key(key_parts, version)?;

        let iv_b64 = playback["iv"].as_str().ok_or_else(|| ExtractorError::extract("no iv"))?;
        let payload_b64 = playback["payload"].as_str().ok_or_else(|| ExtractorError::extract("no payload"))?;
        let iv = URL_SAFE_NO_PAD.decode(iv_b64.trim_end_matches('=')).map_err(|e| ExtractorError::extract(format!("iv decode: {e}")))?;
        let payload = URL_SAFE_NO_PAD.decode(payload_b64.trim_end_matches('=')).map_err(|e| ExtractorError::extract(format!("payload decode: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| ExtractorError::extract(format!("AES init: {e}")))?;
        let nonce_bytes = Nonce::from_slice(&iv);
        let plaintext = cipher.decrypt(nonce_bytes, payload.as_ref()).map_err(|_| ExtractorError::extract("AES failed"))?;
        let decrypted: Value = serde_json::from_slice(&plaintext).map_err(|e| ExtractorError::extract(format!("json parse: {e}")))?;

        // 8. URL FINAL
        let sources = decrypted["sources"].as_array().ok_or_else(|| ExtractorError::extract("no sources"))?;
        let hls = sources.iter().find(|s| s["mime_type"].as_str() == Some("application/vnd.apple.mpegurl") || s["url"].as_str().map(|u| u.contains(".m3u8")).unwrap_or(false))
            .ok_or_else(|| ExtractorError::extract("no HLS source"))?;
        let destination_url = hls["url"].as_str().ok_or_else(|| ExtractorError::extract("no url"))?.to_string();

        let mut result_headers = self.0.base_headers.clone();
        result_headers.insert("referer".into(), referer.into());

        Ok(ExtractorResult { destination_url, request_headers: result_headers, mediaflow_endpoint: "hls_manifest_proxy" })
    }
}
