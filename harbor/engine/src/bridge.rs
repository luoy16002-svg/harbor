//! Bounded adapters for framed transports. Dropping the exposed stream cancels its task.
use crate::transport::BoxStream;
use anyhow::Result;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    task::JoinHandle,
};

pub fn spawn<F, M>(make: M) -> BoxStream
where
    F: Future<Output = Result<()>> + Send + 'static,
    M: FnOnce(Peer) -> F,
{
    let (client, bridge) = tokio::io::duplex(65536);
    let error = Arc::new(Mutex::new(None));
    let shared = error.clone();
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let future = make(Peer {
        stream: bridge,
        clean_shutdown: clean_shutdown.clone(),
    });
    let task = tokio::spawn(async move {
        if let Err(e) = future.await {
            *shared.lock().unwrap() = Some(e.to_string());
        }
    });
    Box::new(Managed {
        client,
        error,
        task,
        done: false,
        clean_shutdown,
    })
}
pub struct Peer {
    stream: DuplexStream,
    clean_shutdown: Arc<AtomicBool>,
}
impl AsyncRead for Peer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Peer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.clean_shutdown.store(true, Ordering::Release);
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
struct Managed {
    client: DuplexStream,
    error: Arc<Mutex<Option<String>>>,
    task: JoinHandle<()>,
    done: bool,
    clean_shutdown: Arc<AtomicBool>,
}
impl AsyncRead for Managed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.client).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                if !self.done && !self.clean_shutdown.load(Ordering::Acquire) {
                    match Pin::new(&mut self.task).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => self.done = true,
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(io::Error::other(error.to_string())));
                        }
                    }
                }
                if let Some(error) = self.error.lock().unwrap().as_ref() {
                    return Poll::Ready(Err(io::Error::other(error.clone())));
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for Managed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return Poll::Ready(Err(io::Error::other(error.clone())));
        }
        Pin::new(&mut self.client).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_shutdown(cx)
    }
}
impl Drop for Managed {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn remote_half_close_does_not_wait_for_upload() {
        let mut stream = spawn(|mut peer| async move {
            peer.write_all(b"response").await?;
            peer.shutdown().await?;
            let mut request = vec![];
            peer.read_to_end(&mut request).await?;
            ensure_request(&request)
        });
        let mut response = vec![];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, b"response");
        stream.write_all(b"still writable").await.unwrap();
        stream.shutdown().await.unwrap();
    }
    fn ensure_request(bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(bytes == b"still writable", "Upload truncated");
        Ok(())
    }
    #[tokio::test]
    async fn authenticated_failure_is_not_silent_eof() {
        let mut stream = spawn(|_peer| async move { anyhow::bail!("AEAD authentication failed") });
        let error = stream.read_u8().await.unwrap_err();
        assert!(error.to_string().contains("AEAD authentication failed"));
    }
}
