//! VMess AEAD framing. Protocol references are recorded in docs/protocols.md.
use crate::{bridge, config::Node, transport::BoxStream, vless};
use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit as _},
};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use sha2::Sha256;
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    fn nested(data: &[u8], keys: &[&[u8]]) -> [u8; 32] {
        if keys.is_empty() {
            return Sha256::digest(data).into();
        }
        let parent = &keys[..keys.len() - 1];
        let key = keys[keys.len() - 1];
        let mut normalized = [0; 64];
        if key.len() > 64 {
            normalized[..32].copy_from_slice(&nested(key, parent));
        } else {
            normalized[..key.len()].copy_from_slice(key);
        }
        let mut inner: Vec<u8> = normalized.iter().map(|v| v ^ 0x36).collect();
        inner.extend(data);
        let mut outer: Vec<u8> = normalized.iter().map(|v| v ^ 0x5c).collect();
        outer.extend(nested(&inner, parent));
        nested(&outer, parent)
    }
    let mut keys = vec![b"VMess AEAD KDF".as_slice()];
    keys.extend(path);
    nested(key, &keys)
}
fn seal(key: &[u8], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(&key[..16])
        .unwrap()
        .encrypt(nonce[..12].into(), Payload { msg: data, aad })
        .map_err(|_| anyhow!("VMess AEAD encryption failed"))
}
fn open(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(&key[..16])
        .unwrap()
        .decrypt(nonce[..12].into(), data)
        .map_err(|_| anyhow!("VMess header authentication failed"))
}
// Keep key schedules inline; boxing would add an allocation to every UDP packet.
#[allow(clippy::large_enum_variant)]
enum Cipher {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}
impl Cipher {
    fn new(key: &[u8], chacha: bool) -> Self {
        if chacha {
            let first = Md5::digest(key);
            let second = Md5::digest(first);
            let mut full = Zeroizing::new([0; 32]);
            full[..16].copy_from_slice(&first);
            full[16..].copy_from_slice(&second);
            Self::ChaCha(ChaCha20Poly1305::new_from_slice(full.as_ref()).unwrap())
        } else {
            Self::Aes(Aes128Gcm::new_from_slice(key).unwrap())
        }
    }
    fn encrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(c) => c.encrypt(nonce.into(), data),
            Self::ChaCha(c) => c.encrypt(nonce.into(), data),
        }
        .map_err(|_| anyhow!("VMess payload encryption failed"))
    }
    fn decrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(c) => c.decrypt(nonce.into(), data),
            Self::ChaCha(c) => c.decrypt(nonce.into(), data),
        }
        .map_err(|_| anyhow!("VMess payload authentication failed"))
    }
}
struct Chunks {
    cipher: Cipher,
    nonce: [u8; 12],
    count: u32,
    mask: Shake128Reader,
}
impl Chunks {
    fn new(key: &[u8], iv: &[u8], chacha: bool) -> Self {
        let mut shake = Shake128::default();
        Update::update(&mut shake, iv);
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&iv[..12]);
        Self {
            cipher: Cipher::new(key, chacha),
            nonce,
            count: 0,
            mask: shake.finalize_xof(),
        }
    }
    fn nonce(&mut self) -> Result<[u8; 12]> {
        ensure!(
            self.count < 65536,
            "VMess session nonce limit reached; reconnect required"
        );
        self.nonce[..2].copy_from_slice(&(self.count as u16).to_be_bytes());
        self.count += 1;
        Ok(self.nonce)
    }
    fn next_mask(&mut self) -> u16 {
        let mut bytes = [0; 2];
        XofReader::read(&mut self.mask, &mut bytes);
        u16::from_be_bytes(bytes)
    }
    async fn write<W: AsyncWrite + Unpin>(&mut self, writer: &mut W, data: &[u8]) -> Result<()> {
        ensure!(data.len() <= 16384, "VMess chunk too large");
        let nonce = self.nonce()?;
        let bytes = self.cipher.encrypt(&nonce, data)?;
        let padding = (self.next_mask() % 64) as usize;
        let length = (bytes.len() + padding) as u16 ^ self.next_mask();
        writer.write_u16(length).await?;
        writer.write_all(&bytes).await?;
        let padding: Vec<u8> = (0..padding).map(|_| rand::random()).collect();
        writer.write_all(&padding).await?;
        Ok(())
    }
    async fn read<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        let raw = reader.read_u16().await?;
        let padding = (self.next_mask() % 64) as usize;
        let length = (raw ^ self.next_mask()) as usize;
        ensure!(
            length >= 16 + padding && length <= 65535,
            "VMess invalid chunk length"
        );
        let mut data = vec![0; length];
        reader.read_exact(&mut data).await?;
        let nonce = self.nonce()?;
        self.cipher.decrypt(&nonce, &data[..length - padding])
    }
}
struct Session {
    upload: Chunks,
    download: Chunks,
    response_key: Zeroizing<[u8; 16]>,
    response_iv: Zeroizing<[u8; 16]>,
    marker: u8,
}
impl Session {
    async fn start(
        stream: &mut BoxStream,
        node: &Node,
        host: &str,
        port: u16,
        udp: bool,
    ) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(&node.uuid)?;
        let mut command_material = Zeroizing::new(uuid.as_bytes().to_vec());
        command_material.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let cmd = Zeroizing::new(<[u8; 16]>::from(Md5::digest(&*command_material)));
        let key = Zeroizing::new(rand::random::<[u8; 16]>());
        let iv = Zeroizing::new(rand::random::<[u8; 16]>());
        let marker = rand::random::<u8>();
        let chacha = node.security == "chacha20-poly1305";
        let mut header = Zeroizing::new(vec![1]);
        header.extend(iv.iter());
        header.extend(key.iter());
        header.extend([
            marker,
            0x0d,
            if chacha { 4 } else { 3 },
            0,
            if udp { 2 } else { 1 },
        ]);
        vless::address(&mut header, host, port)?;
        let checksum = header.iter().fold(2166136261u32, |hash, b| {
            (hash ^ u32::from(*b)).wrapping_mul(16777619)
        });
        header.extend(checksum.to_be_bytes());
        let mut auth = [0u8; 16];
        auth[..8].copy_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .to_be_bytes(),
        );
        auth[8..12].copy_from_slice(&rand::random::<[u8; 4]>());
        let crc = crc32fast::hash(&auth[..12]);
        auth[12..].copy_from_slice(&crc.to_be_bytes());
        let auth_key = kdf(cmd.as_ref(), &[b"AES Auth ID Encryption"]);
        Aes128::new_from_slice(&auth_key[..16])
            .unwrap()
            .encrypt_block((&mut auth).into());
        let connection_nonce = rand::random::<[u8; 8]>();
        let key_len = kdf(
            cmd.as_ref(),
            &[b"VMess Header AEAD Key_Length", &auth, &connection_nonce],
        );
        let iv_len = kdf(
            cmd.as_ref(),
            &[b"VMess Header AEAD Nonce_Length", &auth, &connection_nonce],
        );
        let key_data = kdf(
            cmd.as_ref(),
            &[b"VMess Header AEAD Key", &auth, &connection_nonce],
        );
        let iv_data = kdf(
            cmd.as_ref(),
            &[b"VMess Header AEAD Nonce", &auth, &connection_nonce],
        );
        let mut output = auth.to_vec();
        output.extend(seal(
            &key_len,
            &iv_len,
            &(header.len() as u16).to_be_bytes(),
            &auth,
        )?);
        output.extend(connection_nonce);
        output.extend(seal(&key_data, &iv_data, &header, &auth)?);
        stream.write_all(&output).await?;
        let response_key =
            Zeroizing::new(<[u8; 16]>::try_from(&Sha256::digest(key.as_ref())[..16]).unwrap());
        let response_iv =
            Zeroizing::new(<[u8; 16]>::try_from(&Sha256::digest(iv.as_ref())[..16]).unwrap());
        Ok(Self {
            upload: Chunks::new(key.as_ref(), iv.as_ref(), chacha),
            download: Chunks::new(response_key.as_ref(), response_iv.as_ref(), chacha),
            response_key,
            response_iv,
            marker,
        })
    }
    async fn response<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<()> {
        let mut length = [0; 18];
        reader.read_exact(&mut length).await?;
        let plain = open(
            &kdf(self.response_key.as_ref(), &[b"AEAD Resp Header Len Key"]),
            &kdf(self.response_iv.as_ref(), &[b"AEAD Resp Header Len IV"]),
            &length,
        )?;
        let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        ensure!(
            (4..=1024).contains(&len),
            "VMess response header size invalid"
        );
        let mut body = vec![0; len + 16];
        reader.read_exact(&mut body).await?;
        let header = open(
            &kdf(self.response_key.as_ref(), &[b"AEAD Resp Header Key"]),
            &kdf(self.response_iv.as_ref(), &[b"AEAD Resp Header IV"]),
            &body,
        )?;
        ensure!(header[0] == self.marker, "VMess response marker mismatch");
        ensure!(header[2] == 0, "VMess dynamic commands are not supported");
        Ok(())
    }
}
pub async fn connect(
    mut stream: BoxStream,
    node: &Node,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    let session = Session::start(&mut stream, node, host, port, false).await?;
    Ok(bridge::spawn(move |local| async move {
        let (mut remote_read, mut remote_write) = tokio::io::split(stream);
        let (mut local_read, mut local_write) = tokio::io::split(local);
        // Authenticate the response concurrently with upload: servers may wait for the first application bytes.
        let mut upload = session.upload;
        let response_key = session.response_key;
        let response_iv = session.response_iv;
        let marker = session.marker;
        let mut download = session.download;
        let tx = async {
            let mut buffer = vec![0; 16384];
            loop {
                let n = local_read.read(&mut buffer).await?;
                upload.write(&mut remote_write, &buffer[..n]).await?;
                if n == 0 {
                    remote_write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
            }
        };
        let rx = async {
            let mut length = [0; 18];
            remote_read.read_exact(&mut length).await?;
            let plain = open(
                &kdf(response_key.as_ref(), &[b"AEAD Resp Header Len Key"]),
                &kdf(response_iv.as_ref(), &[b"AEAD Resp Header Len IV"]),
                &length,
            )?;
            let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
            ensure!(
                (4..=1024).contains(&len),
                "VMess response header size invalid"
            );
            let mut body = vec![0; len + 16];
            remote_read.read_exact(&mut body).await?;
            let header = open(
                &kdf(response_key.as_ref(), &[b"AEAD Resp Header Key"]),
                &kdf(response_iv.as_ref(), &[b"AEAD Resp Header IV"]),
                &body,
            )?;
            ensure!(
                header[0] == marker && header[2] == 0,
                "VMess response authentication or command mismatch"
            );
            loop {
                let bytes = download.read(&mut remote_read).await?;
                if bytes.is_empty() {
                    local_write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                local_write.write_all(&bytes).await?;
            }
        };
        tokio::try_join!(tx, rx)?;
        Ok(())
    }))
}
pub async fn udp(
    mut stream: BoxStream,
    node: &Node,
    host: &str,
    port: u16,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut session = Session::start(&mut stream, node, host, port, true).await?;
    session.upload.write(&mut stream, data).await?;
    session.response(&mut stream).await?;
    session.download.read(&mut stream).await
}

pub async fn relay_udp(
    mut stream: BoxStream,
    node: &Node,
    host: &str,
    port: u16,
    mut input: tokio::sync::mpsc::Receiver<Vec<u8>>,
    output: tokio::sync::mpsc::Sender<crate::datagram::Packet>,
) -> Result<()> {
    let session = Session::start(&mut stream, node, host, port, true).await?;
    let (mut read, mut write) = tokio::io::split(stream);
    let mut upload = session.upload;
    let mut download = session.download;
    let key = session.response_key;
    let iv = session.response_iv;
    let marker = session.marker;
    let send = async {
        while let Some(data) = input.recv().await {
            upload.write(&mut write, &data).await?;
        }
        write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let receive = async {
        let mut length = [0; 18];
        read.read_exact(&mut length).await?;
        let plain = open(
            &kdf(key.as_ref(), &[b"AEAD Resp Header Len Key"]),
            &kdf(iv.as_ref(), &[b"AEAD Resp Header Len IV"]),
            &length,
        )?;
        let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        ensure!(
            (4..=1024).contains(&len),
            "VMess response header size invalid"
        );
        let mut body = vec![0; len + 16];
        read.read_exact(&mut body).await?;
        let header = open(
            &kdf(key.as_ref(), &[b"AEAD Resp Header Key"]),
            &kdf(iv.as_ref(), &[b"AEAD Resp Header IV"]),
            &body,
        )?;
        ensure!(
            header[0] == marker && header[2] == 0,
            "VMess response marker or command invalid"
        );
        loop {
            let data = download.read(&mut read).await?;
            if data.is_empty() {
                return Ok::<(), anyhow::Error>(());
            }
            if output
                .send(crate::datagram::Packet {
                    host: host.into(),
                    port,
                    data,
                })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    };
    tokio::select! {result=send=>result,result=receive=>result}
}
