//! SIP004/SIP007 AEAD. Cipher primitives are provided by RustCrypto.
use crate::{
    bridge,
    transport::{BoxStream, write_address},
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

// Keep key schedules inline; boxing would add an allocation to every UDP packet.
#[allow(clippy::large_enum_variant)]
enum Cipher {
    ChaCha(ChaCha20Poly1305),
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}
impl Cipher {
    fn new(method: &str, master: &[u8], salt: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new(vec![0; master.len()]);
        Hkdf::<Sha1>::new(Some(salt), master)
            .expand(b"ss-subkey", &mut key)
            .map_err(|_| anyhow!("HKDF failed"))?;
        Ok(match method {
            "chacha20-ietf-poly1305" => {
                Self::ChaCha(ChaCha20Poly1305::new_from_slice(&key).unwrap())
            }
            "aes-128-gcm" => Self::Aes128(Aes128Gcm::new_from_slice(&key).unwrap()),
            "aes-256-gcm" => Self::Aes256(Aes256Gcm::new_from_slice(&key).unwrap()),
            _ => return Err(anyhow!("Unsupported cipher")),
        })
    }
    fn encrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::ChaCha(c) => c.encrypt(nonce.into(), data),
            Self::Aes128(c) => c.encrypt(nonce.into(), data),
            Self::Aes256(c) => c.encrypt(nonce.into(), data),
        }
        .map_err(|_| anyhow!("AEAD encryption failed"))
    }
    fn decrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::ChaCha(c) => c.decrypt(nonce.into(), data),
            Self::Aes128(c) => c.decrypt(nonce.into(), data),
            Self::Aes256(c) => c.decrypt(nonce.into(), data),
        }
        .map_err(|_| anyhow!("AEAD authentication failed"))
    }
}
fn key_len(method: &str) -> usize {
    if method == "aes-128-gcm" { 16 } else { 32 }
}
fn master_key(password: &str, len: usize) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::new());
    let mut previous = Zeroizing::new(Vec::new());
    while output.len() < len {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password.as_bytes());
        previous = Zeroizing::new(digest.finalize().to_vec());
        output.extend_from_slice(&previous);
    }
    output.truncate(len);
    output
}
fn increment(nonce: &mut [u8; 12]) -> Result<()> {
    for byte in nonce.iter_mut() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            return Ok(());
        }
    }
    Err(anyhow!("AEAD nonce exhausted"))
}
async fn send_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    cipher: &Cipher,
    nonce: &mut [u8; 12],
    data: &[u8],
) -> Result<()> {
    ensure!(data.len() <= 0x3fff, "AEAD chunk too large");
    let len = cipher.encrypt(nonce, &(data.len() as u16).to_be_bytes())?;
    increment(nonce)?;
    let body = cipher.encrypt(nonce, data)?;
    increment(nonce)?;
    writer.write_all(&len).await?;
    writer.write_all(&body).await?;
    Ok(())
}

pub async fn stream(
    stream: BoxStream,
    method: &str,
    password: &str,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    if crate::ss2022::supported(method) {
        return crate::ss2022::stream(stream, method, password, host, port).await;
    }
    let master = master_key(password, key_len(method));
    let salt: Vec<u8> = (0..master.len()).map(|_| rand::random()).collect();
    let cipher = Cipher::new(method, &master, &salt)?;
    let (mut read, mut write) = tokio::io::split(stream);
    write.write_all(&salt).await?;
    let mut address = vec![];
    write_address(&mut address, host, port)?;
    let mut nonce = [0; 12];
    send_chunk(&mut write, &cipher, &mut nonce, &address).await?;
    let method = method.to_string();
    Ok(bridge::spawn(move |local| async move {
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let upload = async {
            let mut buf = [0u8; 0x3fff];
            loop {
                let n = local_read.read(&mut buf).await?;
                if n == 0 {
                    write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                send_chunk(&mut write, &cipher, &mut nonce, &buf[..n]).await?;
            }
        };
        let download = async {
            let mut salt = vec![0; master.len()];
            read.read_exact(&mut salt).await?;
            let cipher = Cipher::new(&method, &master, &salt)?;
            let mut nonce = [0; 12];
            let mut first = true;
            loop {
                let mut len = [0; 18];
                let n = read.read(&mut len[..1]).await?;
                if n == 0 {
                    local_write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                read.read_exact(&mut len[1..]).await?;
                let bytes = cipher.decrypt(&nonce, &len)?;
                increment(&mut nonce)?;
                let size = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                ensure!(size <= 0x3fff, "Invalid AEAD length");
                let mut encrypted = vec![0; size + 16];
                read.read_exact(&mut encrypted).await?;
                let plain = Zeroizing::new(cipher.decrypt(&nonce, &encrypted)?);
                increment(&mut nonce)?;
                if first {
                    check_replay(&master, &salt, b"tcp")?;
                    first = false;
                }
                local_write.write_all(&plain).await?;
            }
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    }))
}
pub fn seal_udp(method: &str, password: &str, plain: &[u8]) -> Result<Vec<u8>> {
    let master = master_key(password, key_len(method));
    let mut salt: Vec<u8> = (0..master.len()).map(|_| rand::random()).collect();
    let cipher = Cipher::new(method, &master, &salt)?;
    salt.extend(cipher.encrypt(&[0; 12], plain)?);
    Ok(salt)
}
pub fn open_udp(method: &str, password: &str, packet: &[u8]) -> Result<Vec<u8>> {
    let len = key_len(method);
    ensure!(packet.len() >= len + 16, "Truncated AEAD datagram");
    let master = master_key(password, len);
    let plain = Cipher::new(method, &master, &packet[..len])?.decrypt(&[0; 12], &packet[len..])?;
    check_replay(&master, &packet[..len], b"udp")?;
    Ok(plain)
}

// Bounded authenticated replay window, shared across associations using the same secret.
fn check_replay(master: &[u8], salt: &[u8], kind: &[u8]) -> Result<()> {
    static SEEN: OnceLock<Mutex<HashMap<[u8; 32], Instant>>> = OnceLock::new();
    let mut digest = Sha256::new();
    digest.update(master);
    digest.update(kind);
    digest.update(salt);
    let key: [u8; 32] = digest.finalize().into();
    let now = Instant::now();
    let mut cache = SEEN
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    if let Some(previous) = cache.get(&key) {
        ensure!(
            now.duration_since(*previous) > Duration::from_secs(600),
            "AEAD replay rejected"
        );
    }
    if cache.len() >= 16384 {
        cache.retain(|_, t| now.duration_since(*t) < Duration::from_secs(600));
        if cache.len() >= 16384 {
            let oldest = cache
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| *k)
                .unwrap();
            cache.remove(&oldest);
        }
    }
    cache.insert(key, now);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aead_integrity_and_unique_salts() {
        for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let a = seal_udp(method, "test password", b"known message").unwrap();
            let b = seal_udp(method, "test password", b"known message").unwrap();
            assert_ne!(a, b);
            assert_eq!(
                open_udp(method, "test password", &a).unwrap(),
                b"known message"
            );
            assert!(
                open_udp(method, "test password", &a).is_err(),
                "Replay accepted"
            );
            let mut tampered = a.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(open_udp(method, "test password", &tampered).is_err());
            assert!(open_udp(method, "wrong password", &a).is_err());
        }
    }
}
