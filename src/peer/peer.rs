//! Peer connection management

use crate::messages::{Addr, Message, Ping, Reject, Version, node_addr_ex::NodeAddrEx};
use crate::network::Network;
use crate::util::{Error, Result, rx};
use log::{debug, error, info, warn};
use std::hash::{Hash, Hasher};
use std::fmt;
use std::io::Write;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::io;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

/// A connection to a remote peer
#[derive(Clone)]
pub struct Peer {
    /// Network used for this peer connection
    pub network: Network,
    /// IP address of the peer
    pub ip: IpAddr,
    /// Port number for the peer
    pub port: u16,
    /// TCP socket for the connection
    socket: Arc<Mutex<Option<TcpStream>>>,
    /// Receiver channel for messages
    rx: Arc<rx::Single<Message>>,
    /// Whether the connection is active
    active: Arc<AtomicBool>,
    /// Whether we initiated the connection
    outbound: bool,
}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.ip == other.ip && self.port == other.port && self.network == other.network
    }
}

impl Eq for Peer {}

impl Hash for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
        self.port.hash(state);
        self.network.hash(state);
    }
}

impl Peer {
    /// Creates a new disconnected peer
    pub fn new(network: Network, ip: IpAddr, port: u16) -> Peer {
        Peer {
            network,
            ip,
            port,
            socket: Arc::new(Mutex::new(None)),
            rx: Arc::new(rx::Single::new()),
            active: Arc::new(AtomicBool::new(false)),
            outbound: false,
        }
    }

    /// Creates a new inbound peer with an established socket
    pub fn new_inbound(network: Network, socket: TcpStream) -> Result<Peer> {
        let addr = socket.peer_addr()?;
        Ok(Peer {
            network,
            ip: addr.ip(),
            port: addr.port(),
            socket: Arc::new(Mutex::new(Some(socket))),
            rx: Arc::new(rx::Single::new()),
            active: Arc::new(AtomicBool::new(true)),
            outbound: false,
        })
    }

    /// Returns whether the peer is connected
    pub fn is_connected(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Sends a message to the peer
    pub fn send(&self, message: Message) -> Result<()> {
        let mut socket = self.socket.lock().map_err(|_| {
            Error::Poison(format!("Failed to lock socket for {}", self))
        })?;
        let socket = socket.as_mut().ok_or_else(|| {
            Error::InvalidOperation(format!("Not connected to {}", self))
        })?;
        debug!("{:?} Write {:#?}", self, message);
        socket.write_all(&message.write_vec()?)?;
        socket.flush()?;
        Ok(())
    }

    /// Disconnects from the peer
    pub fn disconnect(&self) -> Result<()> {
        info!("{:?} Disconnecting", self);
        let mut socket = self.socket.lock().map_err(|_| {
            Error::Poison(format!("Failed to lock socket for {}", self))
        })?;
        if let Some(socket) = socket.take() {
            if let Err(e) = socket.shutdown(Shutdown::Both) {
                warn!("{:?} Problem shutting down tcp stream: {:?}", self, e);
            }
        }
        self.active.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Connects to the peer and performs handshake
    pub fn connect(&self) -> Result<Arc<Peer>> {
        if self.is_connected() {
            return Err(Error::InvalidOperation(format!("Already connected to {}", self)));
        }
        let socket_addr = SocketAddr::new(self.ip, self.port);
        let socket = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let tpeer = Arc::new(Peer {
            network: self.network,
            ip: self.ip,
            port: self.port,
            socket: Arc::new(Mutex::new(Some(socket))),
            rx: Arc::new(rx::Single::new()),
            active: Arc::new(AtomicBool::new(true)),
            outbound: true,
        });
        info!("{:?} Connecting to {:?}:{}", tpeer, tpeer.ip, tpeer.port);
        let weak = Arc::downgrade(&tpeer);
        thread::spawn(move || {
            if let Err(e) = tpeer.handshake() {
                error!("Failed to complete handshake: {:?}", e);
                let _ = tpeer.disconnect();
                return;
            }
            info!("{:?} Connected to {:?}:{}", tpeer, tpeer.ip, tpeer.port);
            let mut socket = match tpeer.socket.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let socket = match socket.as_mut() {
                Some(s) => s,
                None => return,
            };
            let mut bytes = vec![];
            loop {
                match Message::read(socket) {
                    Ok(message) => {
                        debug!("{:?} Read {:#?}", tpeer, message);
                        let weak = weak.clone();
                        if tpeer.rx.send(message, move || {
                            weak.upgrade()
                                .map(|p| p.active.load(Ordering::SeqCst))
                                .unwrap_or(false)
                        }).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("{:?} Error handling message: {:?}", tpeer, e);
                        break;
                    }
                }
                match socket.read_to_end(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(e) => {
                        error!("{:?} Error reading message {:?}", tpeer, e);
                        break;
                    }
                }
            }
            let _ = tpeer.disconnect();
        });
        Ok(tpeer)
    }

    /// Performs the handshake with the peer
    pub fn handshake(&self) -> Result<()> {
        let our_version = Version {
            version: 70015,
            services: 0,
            timestamp: UNIX_EPOCH.elapsed().unwrap().as_secs() as i64,
            addr_from: self.network.node_addr(),
            addr_recv: self.network.node_addr(),
            nonce: rand::random(),
            user_agent: "/rust-sv:0.1.0/".to_string(),
            start_height: 0,
            relay: false,
        };
        debug!("{:?} Write {:#?}", self, our_version);
        self.send(Message::Version(our_version.clone()))?;
        let msg = self.rx.recv(Duration::from_secs(5))?;
        debug!("{:?} Read {:#?}", self, msg);
        let their_version = match msg {
            Message::Version(v) => v,
            _ => return Err(Error::BadData("Expected version message".to_string())),
        };
        let their_verack = self.rx.recv(Duration::from_secs(5))?;
        debug!("{:?} Read {:#?}", self, their_verack);
        if their_verack != Message::Verack {
            return Err(Error::BadData("Expected verack message".to_string()));
        }
        debug!("{:?} Write {:#?}", self, Message::Verack);
        self.send(Message::Verack)?;
        let ping = Ping { nonce: rand::random() };
        debug!("{:?} Write {:#?}", self, ping);
        self.send(Message::Ping(ping.clone()))?;
        let pong = self.rx.recv(Duration::from_secs(5))?;
        if pong != Message::Pong(ping) {
            return Err(Error::BadData("Expected pong message".to_string()));
        }
        Ok(())
    }

    /// Receives a message from the peer
    pub fn recv(&self, timeout: Duration) -> Result<Message> {
        self.rx.recv(timeout)
    }

    /// Gets the address of the peer
    pub fn addr(&self) -> Result<Addr> {
        Ok(Addr {
            addrs: vec![NodeAddrEx {
                last_connected_time: UNIX_EPOCH.elapsed().unwrap().as_secs() as u32,
                addr: self.network.node_addr(),
            }],
        })
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Peer")
            .field("network", &self.network)
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("outbound", &self.outbound)
            .field("active", &self.is_connected())
            .finish()
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{} ({})", self.ip, self.port, self.network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_peer() {
        let peer = Peer::new(Network::Mainnet, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8333);
        assert!(!peer.is_connected());
        assert_eq!(peer.network, Network::Mainnet);
        assert_eq!(peer.ip, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(peer.port, 8333);
    }
}
