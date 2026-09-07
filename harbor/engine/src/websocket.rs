use crate::{bridge, config::Node, transport::BoxStream};
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, http::HeaderValue, protocol::WebSocketConfig,
};

pub async fn connect(stream: BoxStream, node: &Node) -> Result<BoxStream> {
    let authority = if node.server.contains(':') {
        format!("[{}]:{}", node.server, node.port)
    } else {
        format!("{}:{}", node.server, node.port)
    };
    let mut request = format!(
        "{}://{}{}",
        if node.tls || node.kind == crate::config::NodeKind::Trojan {
            "wss"
        } else {
            "ws"
        },
        authority,
        node.ws_path
    )
    .into_client_request()?;
    if !node.ws_host.is_empty() {
        request
            .headers_mut()
            .insert("Host", HeaderValue::from_str(&node.ws_host)?);
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(1024 * 1024))
        .max_frame_size(Some(1024 * 1024));
    let (ws, _) = tokio_tungstenite::client_async_with_config(request, stream, Some(config))
        .await
        .context("WebSocket handshake failed")?;
    Ok(bridge::spawn(move |local| async move {
        let (mut sink, mut source) = ws.split();
        let (mut read, mut write) = tokio::io::split(local);
        let upload = async {
            let mut buffer = vec![0; 32768];
            loop {
                let n = read.read(&mut buffer).await?;
                if n == 0 {
                    sink.close().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                sink.send(Message::Binary(buffer[..n].to_vec().into()))
                    .await?;
            }
        };
        let download = async {
            while let Some(frame) = source.next().await {
                match frame? {
                    Message::Binary(bytes) => write.write_all(&bytes).await?,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => {}
                    Message::Text(_) => ensure!(false, "Unexpected text frame in proxy transport"),
                    Message::Frame(_) => {}
                }
            }
            write.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    }))
}
