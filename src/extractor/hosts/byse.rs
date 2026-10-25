use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core::RngCore;
use serde_json::{json, Value};
use std::collections::HashMap;

// ════════════════════════════════════════════════
//  ALGORITMO POW DE BYSE (Traducido a Rust)
// ════════════════════════════════════════════════
const BE: usize = 512;
const LT: usize = BE - 1;
const DR: usize = 2;
const LR: u32 = 2654435761;
const HR: u32 = 2246822519;

fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

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
    for _ in 0..8 {
        ye(&mut e);
    }
    let mut r = [0u32; BE];
    for i in 0..BE {
        ye(&mut e);
        r[i] = e[0] ^ e[2];
    }
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
        if n == 0 {
            e += 32;
            continue;
        }
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
        if wr(&hash) >= difficulty {
            return solution.to_string();
        }
        solution += 1;
    }
}

// ════════════════════════════════════════════════
//  EXTRACTOR PRINCIPAL
// ════════════════════════════════════════════════
pub async fn extract_byse(
    client: &reqwest::Client,
    embed_url: &str,
) -> Result<Value, String> {
    // 1. Extraer el ID del video (lavu1tiombaz)
    let video_id = embed_url
        .split("/e/")
        .last()
        .ok_or("Invalid embed URL")?
        .split(&['?', '#'][..])
        .next()
        .ok_or("Invalid embed URL")?;

    let base_url = "https://n1mwq.org";
    let referer = embed_url;
    let origin = "https://n1mwq.org";

    // 2. Challenge
    let challenge_url = format!("{}/api/videos/access/challenge", base_url);
    let challenge_res = client
        .post(&challenge_url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
        .header("Referer", referer)
        .header("Origin", origin)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let challenge_json: Value = challenge_res.json().await.map_err(|e| e.to_string())?;
    let challenge_id = challenge_json["challenge_id"].as_str().ok_or("No challenge_id")?;
    let nonce = challenge_json["nonce"].as_str().ok_or("No nonce")?;

    // 3. Generar llaves ECDSA P-256 y firmar
    let mut csprng = rand_core::OsRng;
    let signing_key = SigningKey::random(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    
    // Construir JWK
    let x = URL_SAFE_NO_PAD.encode(&public_key.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(&public_key.y().unwrap());
    
    let signature: Signature = signing_key.sign(nonce.as_bytes());
    let sig_bytes = signature.to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

    // 4. Attest
    let attest_url = format!("{}/api/videos/access/attest", base_url);
    let attest_body = json!({
        "viewer_id": "AtuauIaIq2YSMIBc-Ull4A",
        "device_id": "fqWjmX5ayBvC_eCFbYqiqw",
        "challenge_id": challenge_id,
        "nonce": nonce,
        "signature": sig_b64,
        "public_key": {
            "crv": "P-256",
            "ext": true,
            "key_ops": ["verify"],
            "kty": "EC",
            "x": x,
            "y": y
        }
    });

    let attest_res = client
        .post(&attest_url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
        .header("Referer", referer)
        .header("Origin", origin)
        .json(&attest_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let attest_json: Value = attest_res.json().await.map_err(|e| e.to_string())?;
    let token = attest_json["token"].as_str().ok_or("No token")?;

    // 5. Captcha
    let captcha_url = format!("{}/api/videos/{}/embed/captcha", base_url, video_id);
    let captcha_body = json!({
        "fingerprint": {
            "token": token,
            "viewer_id": "AtuauIaIq2YSMIBc-Ull4A",
            "device_id": "fqWjmX5ayBvC_eCFbYqiqw",
            "confidence": 0.93
        }
    });

    let captcha_res = client
        .post(&captcha_url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
        .header("Referer", referer)
        .header("Origin", origin)
        .json(&captcha_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let captcha_json: Value = captcha_res.json().await.map_err(|e| e.to_string())?;
    let pow_token = captcha_json["pow_token"].as_str().ok_or("No pow_token")?;
    let pow_nonce = captcha_json["pow_nonce"].as_str().ok_or("No pow_nonce")?;
    let pow_difficulty = captcha_json["pow_difficulty"].as_u64().unwrap_or(16) as u32;

    // 6. Resolver PoW
    let solution = solve_pow(pow_nonce, pow_difficulty);

    // 7. Verify
    let verify_url = format!("{}/api/videos/{}/embed/captcha/verify", base_url, video_id);
    let verify_body = json!({
        "pow_token": pow_token,
        "solution": solution,
        "fingerprint": {
            "token": token,
            "viewer_id": "AtuauIaIq2YSMIBc-Ull4A",
            "device_id": "fqWjmX5ayBvC_eCFbYqiqw",
            "confidence": 0.93
        }
    });

    let verify_res = client
        .post(&verify_url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
        .header("Referer", referer)
        .header("Origin", origin)
        .json(&verify_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let verify_json: Value = verify_res.json().await.map_err(|e| e.to_string())?;
    let captcha_token = verify_json["token"].as_str().ok_or("No captcha_token")?;

    // 8. Playback
    let playback_url = format!("{}/api/videos/{}/embed/playback", base_url, video_id);
    let playback_body = json!({
        "fingerprint": {
            "token": token,
            "viewer_id": "AtuauIaIq2YSMIBc-Ull4A",
            "device_id": "fqWjmX5ayBvC_eCFbYqiqw",
            "confidence": 0.93
        }
    });

    let playback_res = client
        .post(&playback_url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
        .header("Referer", referer)
        .header("Origin", origin)
        .header("x-captcha-token", captcha_token)
        .json(&playback_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let playback_json: Value = playback_res.json().await.map_err(|e| e.to_string())?;
    let playback = playback_json["playback"].as_object().ok_or("No playback")?;

    // 9. Descifrar
    let key_parts = playback["key_parts"].as_array().ok_or("No key_parts")?;
    let version = playback["version"].as_str().unwrap_or("1").parse::<usize>().map_err(|_| "Invalid version")?;
    let iv_b64 = playback["iv"].as_str().ok_or("No iv")?;
    let payload_b64 = playback["payload"].as_str().ok_or("No payload")?;

    let i1 = version - 1;
    let i2 = 30 - version;
    if i1 >= key_parts.len() || i2 >= key_parts.len() {
        return Err("Key index out of bounds".to_string());
    }

    let part1 = key_parts[i1].as_str().ok_or("Invalid key part")?;
    let part2 = key_parts[i2].as_str().ok_or("Invalid key part")?;

    let mut key_bytes = Vec::new();
    key_bytes.extend(URL_SAFE_NO_PAD.decode(part1).map_err(|e| e.to_string())?);
    key_bytes.extend(URL_SAFE_NO_PAD.decode(part2).map_err(|e| e.to_string())?);
    
    if key_bytes.len() < 32 {
        return Err("Key too short".to_string());
    }
    let key = &key_bytes[..32];

    let iv = URL_SAFE_NO_PAD.decode(iv_b64).map_err(|e| e.to_string())?;
    let ciphertext = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|e| e.to_string())?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&iv);
    
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| e.to_string())?;
    let decrypted_json: Value = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;

    Ok(decrypted_json)
}
