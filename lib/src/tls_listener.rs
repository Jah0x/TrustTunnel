use crate::{log_utils, tls_demultiplexer};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use tls_parser::{parse_tls_plaintext, TlsMessage};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, StartHandshake};

pub(crate) struct TlsListener {}

pub(crate) struct TlsAcceptor {
    inner: StartHandshake<TcpStream>,
    client_random: Option<Vec<u8>>,
}

impl TlsListener {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn listen(&self, stream: TcpStream) -> io::Result<TlsAcceptor> {
        // Peek at the first 1024 bytes to parse Client Hello
        let mut buffer = vec![0u8; 1024];
        let bytes_peeked = stream.peek(&mut buffer).await?;

        // Extract client_random from the peeked data
        let client_random = Self::extract_client_random(&buffer[..bytes_peeked]);

        // Now let rustls handle the stream normally
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
            .await
            .map(|hs| TlsAcceptor {
                inner: hs,
                client_random,
            })
    }

    fn extract_client_random(data: &[u8]) -> Option<Vec<u8>> {
        // Parse TLS plaintext record
        match parse_tls_plaintext(data) {
            Ok((_, plaintext)) => {
                // Look for handshake messages
                for message in &plaintext.msg {
                    if let TlsMessage::Handshake(handshake) = message {
                        // Check if this is a ClientHello handshake
                        if matches!(handshake, tls_parser::TlsMessageHandshake::ClientHello(..)) {
                            // Extract the ClientHello data
                            if let tls_parser::TlsMessageHandshake::ClientHello(client_hello) =
                                handshake
                            {
                                if client_hello.random.len() >= 32 {
                                    let client_random = client_hello.random[..32].to_vec();

                                    return Some(client_random);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => log::debug!("Failed to parse TLS plaintext: {:?}", e),
        }
        None
    }
}

impl TlsAcceptor {
    pub fn sni(&self) -> Option<String> {
        self.inner.client_hello().server_name().map(String::from)
    }

    pub fn alpn(&self) -> Vec<Vec<u8>> {
        self.inner
            .client_hello()
            .alpn()
            .map(|x| x.map(Vec::from).collect())
            .unwrap_or_default()
    }

    pub fn client_random(&self) -> Option<Vec<u8>> {
        self.client_random.clone()
    }

    pub async fn accept(
        self,
        protocol: tls_demultiplexer::Protocol,
        cert_chain: Vec<Certificate>,
        key: PrivateKey,
        _log_id: &log_utils::IdChain<u64>,
    ) -> io::Result<TlsStream<TcpStream>> {
        let tls_config = {
            let mut cfg = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)
                .map_err(|e| {
                    io::Error::new(
                        ErrorKind::Other,
                        format!("Failed to create TLS configuration: {}", e),
                    )
                })?;

            cfg.alpn_protocols = vec![protocol.as_alpn().as_bytes().to_vec()];
            Arc::new(cfg)
        };

        self.inner.into_stream(tls_config).await
    }
}
