//! SIP022 AES-GCM client. Authentication, replay and request/session binding are mandatory.
use crate::{
    bridge,
    transport::{self, BoxStream},
};
use aes::{
    Aes128, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt},
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub fn supported(method: &str) -> bool {
    matches!(
        method,
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"
    )
}
pub fn validate_key(method: &str, password: &str) -> Result<()> {
    Key::new(method, password).map(|_| ())
}
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn validate_time(bytes: &[u8]) -> Result<()> {
    let sent = u64::from_be_bytes(bytes.try_into().context("Invalid SS2022 timestamp")?);
    ensure!(
        timestamp().abs_diff(sent) <= 30,
        "SS2022 timestamp outside the replay window"
    );
    Ok(())
}
#[allow(clippy::large_enum_variant)]
enum HeaderCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}
struct Key {
    bytes: Zeroizing<Vec<u8>>,
    header: HeaderCipher,
}
impl Key {
    fn new(method: &str, password: &str) -> Result<Self> {
        ensure!(supported(method), "Unsupported SS2022 cipher");
        ensure!(
            !password.contains(':'),
            "SS2022 identity-header key chains are not supported"
        );
        let bytes = Zeroizing::new(
            STANDARD
                .decode(password)
                .context("SS2022 requires a Base64-encoded random PSK")?,
        );
        let expected = if method == "2022-blake3-aes-128-gcm" {
            16
        } else {
            32
        };
        ensure!(bytes.len() == expected, "SS2022 PSK has the wrong length");
        let header = if expected == 16 {
            HeaderCipher::Aes128(Aes128::new_from_slice(&bytes)?)
        } else {
            HeaderCipher::Aes256(Aes256::new_from_slice(&bytes)?)
        };
        Ok(Self { bytes, header })
    }
    fn cipher(&self, salt: &[u8]) -> Result<Cipher> {
        let mut material = Zeroizing::new(self.bytes.to_vec());
        material.extend_from_slice(salt);
        let derived = Zeroizing::new(blake3::derive_key(
            "shadowsocks 2022 session subkey",
            &material,
        ));
        Ok(if self.bytes.len() == 16 {
            Cipher::Aes128(Aes128Gcm::new_from_slice(&derived[..16])?)
        } else {
            Cipher::Aes256(Aes256Gcm::new_from_slice(&derived[..])?)
        })
    }
    fn header(&self, bytes: &mut [u8; 16], encrypt: bool) {
        match (&self.header, encrypt) {
            (HeaderCipher::Aes128(cipher), true) => cipher.encrypt_block(bytes.into()),
            (HeaderCipher::Aes128(cipher), false) => cipher.decrypt_block(bytes.into()),
            (HeaderCipher::Aes256(cipher), true) => cipher.encrypt_block(bytes.into()),
            (HeaderCipher::Aes256(cipher), false) => cipher.decrypt_block(bytes.into()),
        }
    }
}
#[allow(clippy::large_enum_variant)]
enum Cipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}
impl Cipher {
    fn seal(&self, nonce: &[u8; 12], bytes: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes128(c) => c.encrypt(nonce.into(), bytes),
            Self::Aes256(c) => c.encrypt(nonce.into(), bytes),
        }
        .map_err(|_| anyhow!("SS2022 encryption failed"))
    }
    fn open(&self, nonce: &[u8; 12], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Aes128(c) => c.decrypt(nonce.into(), bytes),
            Self::Aes256(c) => c.decrypt(nonce.into(), bytes),
        }
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("SS2022 authentication failed"))
    }
}
fn increment(nonce: &mut [u8; 12]) -> Result<()> {
    for byte in nonce {
        let (value, overflow) = byte.overflowing_add(1);
        *byte = value;
        if !overflow {
            return Ok(());
        }
    }
    Err(anyhow!("SS2022 nonce exhausted"))
}
async fn send_chunk<W: AsyncWriteExt + Unpin>(
    write: &mut W,
    cipher: &Cipher,
    nonce: &mut [u8; 12],
    bytes: &[u8],
) -> Result<()> {
    ensure!(bytes.len() <= 65535, "SS2022 payload is too large");
    let mut wire = cipher.seal(nonce, &(bytes.len() as u16).to_be_bytes())?;
    increment(nonce)?;
    wire.extend(cipher.seal(nonce, bytes)?);
    increment(nonce)?;
    write.write_all(&wire).await?;
    Ok(())
}
pub async fn stream(
    mut stream: BoxStream,
    method: &str,
    password: &str,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    let key = Key::new(method, password)?;
    let request_salt: Vec<u8> = (0..key.bytes.len()).map(|_| rand::random()).collect();
    let cipher = key.cipher(&request_salt)?;
    let mut nonce = [0; 12];
    let padding: u16 = rand::random_range(1..=900);
    let mut variable = Zeroizing::new(Vec::new());
    transport::write_address(&mut variable, host, port)?;
    variable.extend_from_slice(&padding.to_be_bytes());
    variable.extend((0..padding).map(|_| rand::random::<u8>()));
    let mut fixed = vec![0];
    fixed.extend(timestamp().to_be_bytes());
    fixed.extend((variable.len() as u16).to_be_bytes());
    let mut header = request_salt.clone();
    header.extend(cipher.seal(&nonce, &fixed)?);
    increment(&mut nonce)?;
    header.extend(cipher.seal(&nonce, &variable)?);
    increment(&mut nonce)?;
    // Coalesce salt and both header records into one buffer.
    stream.write_all(&header).await?;
    let (mut read, mut write) = tokio::io::split(stream);
    Ok(bridge::spawn(move |local| async move {
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let upload = async {
            let mut bytes = Zeroizing::new(vec![0; 32768]);
            loop {
                let length = local_read.read(&mut bytes).await?;
                if length == 0 {
                    write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                send_chunk(&mut write, &cipher, &mut nonce, &bytes[..length]).await?;
            }
        };
        let download = async {
            let salt_len = key.bytes.len();
            let mut header = vec![0; salt_len * 2 + 27];
            let length = read.read(&mut header).await?;
            ensure!(length == header.len(), "Incomplete SS2022 response header");
            let cipher = key.cipher(&header[..salt_len])?;
            let mut nonce = [0; 12];
            let fixed = cipher.open(&nonce, &header[salt_len..])?;
            increment(&mut nonce)?;
            ensure!(fixed[0] == 1, "SS2022 response has the wrong message type");
            validate_time(&fixed[1..9])?;
            ensure!(
                fixed[9..9 + salt_len] == request_salt,
                "SS2022 response belongs to another request"
            );
            let mut size = u16::from_be_bytes(fixed[9 + salt_len..].try_into().unwrap()) as usize;
            loop {
                let mut body = vec![0; size + 16];
                read.read_exact(&mut body).await?;
                let plain = cipher.open(&nonce, &body)?;
                increment(&mut nonce)?;
                local_write.write_all(&plain).await?;
                let mut length = [0; 18];
                if read.read(&mut length[..1]).await? == 0 {
                    local_write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                read.read_exact(&mut length[1..]).await?;
                let plain = cipher.open(&nonce, &length)?;
                increment(&mut nonce)?;
                size = u16::from_be_bytes(plain[..].try_into().unwrap()) as usize;
            }
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    }))
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u128,
}
impl ReplayWindow {
    fn accepts(&self, id: u64) -> bool {
        self.highest.is_none_or(|highest| {
            id > highest || highest - id < 128 && self.seen & (1 << (highest - id)) == 0
        })
    }
    fn commit(&mut self, id: u64) {
        if let Some(highest) = self.highest {
            if id > highest {
                let shift = id - highest;
                self.seen = if shift >= 128 {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.highest = Some(id);
            } else {
                self.seen |= 1 << (highest - id);
            }
        } else {
            self.highest = Some(id);
            self.seen = 1;
        }
    }
}
pub struct UdpSender {
    key: Arc<Key>,
    client: [u8; 8],
    next: u64,
    cipher: Cipher,
}
struct ServerSession {
    window: ReplayWindow,
    cipher: Cipher,
    last_seen: Instant,
}
pub struct UdpReceiver {
    key: Arc<Key>,
    client: [u8; 8],
    servers: HashMap<[u8; 8], ServerSession>,
}
pub fn udp(method: &str, password: &str) -> Result<(UdpSender, UdpReceiver)> {
    let key = Arc::new(Key::new(method, password)?);
    let client = rand::random();
    Ok((
        UdpSender {
            key: key.clone(),
            client,
            next: 0,
            cipher: key.cipher(&client)?,
        },
        UdpReceiver {
            key,
            client,
            servers: HashMap::new(),
        },
    ))
}
impl UdpSender {
    pub fn seal(&mut self, host: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
        let id = self.next;
        self.next = id
            .checked_add(1)
            .context("SS2022 packet counter exhausted")?;
        let mut header = [0; 16];
        header[..8].copy_from_slice(&self.client);
        header[8..].copy_from_slice(&id.to_be_bytes());
        let mut body = Zeroizing::new(vec![0]);
        body.extend(timestamp().to_be_bytes());
        body.extend([0, 0]);
        transport::write_address(&mut body, host, port)?;
        body.extend(payload);
        ensure!(body.len() + 32 <= 65507, "SS2022 UDP payload too large");
        let encrypted = self.cipher.seal(header[4..].try_into().unwrap(), &body)?;
        self.key.header(&mut header, true);
        let mut packet = header.to_vec();
        packet.extend(encrypted);
        Ok(packet)
    }
}
impl UdpReceiver {
    pub fn open(&mut self, packet: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            packet.len() >= 16 + 19 + 7 + 16,
            "Truncated SS2022 UDP response"
        );
        let mut header: [u8; 16] = packet[..16].try_into().unwrap();
        self.key.header(&mut header, false);
        let session: [u8; 8] = header[..8].try_into().unwrap();
        let id = u64::from_be_bytes(header[8..].try_into().unwrap());
        ensure!(session != self.client, "SS2022 reflected UDP session");
        if let Some(server) = self.servers.get(&session) {
            ensure!(server.window.accepts(id), "SS2022 UDP replay");
        }
        let new_cipher;
        let cipher = if let Some(server) = self.servers.get(&session) {
            &server.cipher
        } else {
            new_cipher = self.key.cipher(&session)?;
            &new_cipher
        };
        let body = cipher.open(header[4..].try_into().unwrap(), &packet[16..])?;
        ensure!(
            body.len() >= 19 && body[0] == 1,
            "Wrong SS2022 UDP message type"
        );
        validate_time(&body[1..9])?;
        ensure!(
            body[9..17] == self.client,
            "SS2022 UDP belongs to another client session"
        );
        let padding = u16::from_be_bytes(body[17..19].try_into().unwrap()) as usize;
        ensure!(19 + padding < body.len(), "Invalid SS2022 UDP padding");
        let plain = Zeroizing::new(body[19 + padding..].to_vec());
        transport::parse_address(&plain)?;
        // Update replay state only after authentication, timestamp, direction and client binding succeed.
        if !self.servers.contains_key(&session) {
            self.servers
                .retain(|_, server| server.last_seen.elapsed() < Duration::from_secs(60));
            ensure!(
                self.servers.len() < 8,
                "Too many recent SS2022 server sessions"
            );
            self.servers.insert(
                session,
                ServerSession {
                    window: Default::default(),
                    cipher: self.key.cipher(&session)?,
                    last_seen: Instant::now(),
                },
            );
        }
        let server = self.servers.get_mut(&session).unwrap();
        server.window.commit(id);
        server.last_seen = Instant::now();
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_authentication_session_binding_and_replay_window() {
        for method in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] {
            let password = STANDARD.encode(vec![7; if method.contains("128") { 16 } else { 32 }]);
            let (_, mut receiver) = udp(method, &password).unwrap();
            let server = [4; 8];
            let cipher = receiver.key.cipher(&server).unwrap();
            let packet = |id: u64, client: [u8; 8], time: u64| {
                let mut header = [0; 16];
                header[..8].copy_from_slice(&server);
                header[8..].copy_from_slice(&id.to_be_bytes());
                let mut body = vec![1];
                body.extend(time.to_be_bytes());
                body.extend(client);
                body.extend([0, 0]);
                transport::write_address(&mut body, "127.0.0.1", 5000).unwrap();
                body.extend(b"fixture");
                let encrypted = cipher.seal(header[4..].try_into().unwrap(), &body).unwrap();
                receiver.key.header(&mut header, true);
                let mut bytes = header.to_vec();
                bytes.extend(encrypted);
                bytes
            };
            let valid = packet(9, receiver.client, timestamp());
            let older = packet(8, receiver.client, timestamp());
            let wrong_client = packet(10, [8; 8], timestamp());
            let expired = packet(10, receiver.client, timestamp() - 31);
            let future = packet(10, receiver.client, timestamp());
            let mut tampered = future.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(receiver.open(&valid).is_ok());
            assert!(receiver.open(&valid).is_err());
            assert!(receiver.open(&older).is_ok());
            for invalid in [wrong_client, expired, tampered] {
                assert!(receiver.open(&invalid).is_err());
            }
            assert!(
                receiver.open(&future).is_ok(),
                "Invalid packets advanced the replay window"
            );
        }
    }
}
