use anyhow::Result;
use quinn::{Endpoint, RecvStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::types::Message;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::net::UdpSocket;

pub struct Network {
    endpoint: Endpoint,
    peers: Arc<Mutex<HashMap<SocketAddr, quinn::Connection>>>,
    message_tx: mpsc::Sender<(SocketAddr, Message)>,
}

impl Network {
    pub async fn new(addr: SocketAddr, message_tx: mpsc::Sender<(SocketAddr, Message)>) -> Result<Arc<Self>> {
        let endpoint = make_server_endpoint(addr)?;
        
        let network = Arc::new(Self {
            endpoint,
            peers: Arc::new(Mutex::new(HashMap::new())),
            message_tx,
        });

        let network_clone = network.clone();
        tokio::spawn(async move {
            while let Some(conn) = network_clone.endpoint.accept().await {
                let network_inner = network_clone.clone();
                tokio::spawn(async move {
                    let _ = network_inner.handle_incoming_connection(conn).await;
                });
            }
        });

        Ok(network)
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<()> {
        let conn = self.endpoint.connect(addr, "localhost")?.await?;
        self.peers.lock().await.insert(addr, conn.clone());
        
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            while let Ok((_send, mut recv)) = conn.accept_bi().await {
                let tx_inner = tx.clone();
                tokio::spawn(async move {
                    let _ = handle_stream(addr, &mut recv, tx_inner).await;
                });
            }
        });
        Ok(())
    }

    pub async fn handle_incoming_connection(&self, conn: quinn::Incoming) -> Result<()> {
        let connection = conn.await?;
        let addr = connection.remote_address();
        self.peers.lock().await.insert(addr, connection.clone());

        while let Ok((_send, mut recv)) = connection.accept_bi().await {
            let tx = self.message_tx.clone();
            tokio::spawn(async move {
                let _ = handle_stream(addr, &mut recv, tx).await;
            });
        }
        Ok(())
    }

    pub async fn broadcast(&self, msg: &Message) -> Result<()> {
        let data = bincode::serialize(msg)?;
        let peers = self.peers.lock().await;
        for (_addr, conn) in peers.iter() {
            let conn = conn.clone();
            let data = data.clone();
            tokio::spawn(async move {
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = send.write_all(&data).await;
                    let _ = send.finish();
                }
            });
        }
        Ok(())
    }

    pub async fn send_to(&self, addr: SocketAddr, msg: &Message) -> Result<()> {
        let data = bincode::serialize(msg)?;
        let peers = self.peers.lock().await;
        if let Some(conn) = peers.get(&addr) {
            let conn = conn.clone();
            tokio::spawn(async move {
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = send.write_all(&data).await;
                    let _ = send.finish();
                }
            });
        }
        Ok(())
    }
}

async fn handle_stream(_addr: SocketAddr, recv: &mut RecvStream, tx: mpsc::Sender<(SocketAddr, Message)>) -> Result<()> {
    let data = recv.read_to_end(10 * 1024 * 1024).await?; // 10MB limit
    let msg: Message = bincode::deserialize(&data)?;
    let _ = tx.send((_addr, msg)).await;
    Ok(())
}

fn make_server_endpoint(bind_addr: SocketAddr) -> Result<Endpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key_der = cert.key_pair.serialize_der();
    
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_der.into());
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];

    let rustls_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;
    
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server_config)?));
    
    let roots = rustls::RootCertStore::empty();
    let mut rustls_client_config = rustls::client::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    rustls_client_config.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));
    
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_config)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_config)));

    Ok(endpoint)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
