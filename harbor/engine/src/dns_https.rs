use crate::{config::DnsTlsServer, dns::validate_response, transport::BoxStream};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use hickory_proto::op::Message;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, client::conn::http1::SendRequest, header};
use hyper_util::rt::TokioIo;

/// One HTTP/1.1 connection; the resolver owns the bounded pool and timeouts.
/// Dropping an interrupted exchange also drops this connection, including its driver.
pub(crate) struct HttpsConnection {
    sender: SendRequest<Full<Bytes>>,
    driver: tokio::task::JoinHandle<Result<(), hyper::Error>>,
}
impl Drop for HttpsConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl HttpsConnection {
    pub async fn connect(stream: BoxStream) -> Result<Self> {
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(16384)
            .handshake(TokioIo::new(stream))
            .await?;
        Ok(Self {
            sender,
            driver: tokio::spawn(connection),
        })
    }
    pub async fn exchange(
        &mut self,
        settings: &DnsTlsServer,
        request: &Message,
    ) -> Result<Message> {
        self.sender.ready().await.context("DoH connection closed")?;
        let original_id = request.id;
        let mut query = request.clone();
        query.metadata.id = 0;
        let wire = query.to_vec()?;
        let host = if settings.server_name.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", settings.server_name)
        } else {
            settings.server_name.clone()
        };
        let authority = if settings.address.port() == 443 {
            host
        } else {
            format!("{}:{}", host, settings.address.port())
        };
        let request = Request::builder()
            .method("POST")
            .uri(settings.https_path.as_deref().context("Missing DoH path")?)
            .header(header::HOST, authority)
            .header(header::ACCEPT, "application/dns-message")
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::from(wire)))?;
        let response = self
            .sender
            .send_request(request)
            .await
            .context("DoH HTTP request failed")?;
        ensure!(
            response.status() == StatusCode::OK,
            "DoH returned HTTP {}",
            response.status()
        );
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        ensure!(
            content_type
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message")),
            "DoH returned an unexpected Content-Type"
        );
        let wire = Limited::new(response.into_body(), 65535)
            .collect()
            .await
            .map_err(|error| {
                anyhow::anyhow!("DoH response is invalid or exceeds 65535 bytes: {error}")
            })?
            .to_bytes();
        ensure!(wire.len() >= 12, "DoH returned a truncated DNS message");
        let mut response =
            Message::from_vec(&wire).context("DoH returned an invalid DNS message")?;
        validate_response(&query, &response)?;
        response.metadata.id = original_id;
        Ok(response)
    }
}
