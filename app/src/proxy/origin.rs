//! Which program opened a connection to the proxy.
//!
//! A client's loopback connection to the proxy shows up twice in the TCP
//! table: once as the proxy's accepted socket and once as the client's own,
//! owned by the client's process. The client's end is the row whose local
//! address is the peer address the proxy sees.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};

use crate::process::exe_name;

/// How long a connection's owner and a process id's exe name are remembered. Short: a port number
/// can be reused by another program once its connection is gone, and a process id once its
/// process has ended.
const TTL: Duration = Duration::from_secs(10);

/// Maps proxy clients to exe names, caching both steps because walking the
/// TCP table and the process list costs milliseconds.
#[derive(Debug)]
pub(super) struct Origin {
    /// The port the proxy listens on: the remote end of every client row.
    proxy_port: u16,
    owners: Mutex<HashMap<SocketAddr, (u32, Instant)>>,
    names: Mutex<HashMap<u32, (Arc<str>, Instant)>>,
}

impl Origin {
    pub(super) fn new(proxy_port: u16) -> Self {
        Self {
            proxy_port,
            owners: Mutex::default(),
            names: Mutex::default(),
        }
    }

    /// Lowercase exe name (`chrome.exe`) of the process on the other end of
    /// the connection from `client`; `None` when it cannot be told (the
    /// connection is gone, or the lookup failed).
    ///
    /// Blocking: call it from a blocking thread.
    pub(super) fn exe_for_client(&self, client: SocketAddr) -> Option<Arc<str>> {
        self.exe_at(Instant::now(), client)
    }

    fn exe_at(&self, now: Instant, client: SocketAddr) -> Option<Arc<str>> {
        let pid = self.owner_of(now, client)?;
        self.name_of(now, pid)
    }

    fn owner_of(&self, now: Instant, client: SocketAddr) -> Option<u32> {
        if let Some(&(pid, at)) = lock(&self.owners).get(&client)
            && now.saturating_duration_since(at) <= TTL
        {
            return Some(pid);
        }
        // The scan runs without the lock; two threads asking for the same
        // client may both scan, which is only a little wasted work.
        let pid = scan_for_owner(client, self.proxy_port)?;
        let mut owners = lock(&self.owners);
        owners.retain(|_, &mut (_, at)| now.saturating_duration_since(at) <= TTL);
        owners.insert(client, (pid, now));
        Some(pid)
    }

    fn name_of(&self, now: Instant, pid: u32) -> Option<Arc<str>> {
        if let Some((name, at)) = lock(&self.names).get(&pid)
            && now.saturating_duration_since(*at) <= TTL
        {
            return Some(Arc::clone(name));
        }
        let name: Arc<str> = Arc::from(exe_name(pid)?);
        let mut names = lock(&self.names);
        names.retain(|_, (_, at)| now.saturating_duration_since(*at) <= TTL);
        names.insert(pid, (Arc::clone(&name), now));
        Some(name)
    }
}

/// Process id owning the client's end of its connection to `proxy_port`.
fn scan_for_owner(client: SocketAddr, proxy_port: u16) -> Option<u32> {
    let family = if client.is_ipv4() {
        AddressFamilyFlags::IPV4
    } else {
        AddressFamilyFlags::IPV6
    };
    get_sockets_info(family, ProtocolFlags::TCP)
        .ok()?
        .into_iter()
        .find_map(|socket| match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp)
                if tcp.local_addr == client.ip()
                    && tcp.local_port == client.port()
                    && tcp.remote_port == proxy_port =>
            {
                // Pid 0 owns sockets that are closing: nobody to name.
                socket
                    .associated_pids
                    .first()
                    .copied()
                    .filter(|&pid| pid != 0)
            }
            _ => None,
        })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // The maps only cache; a panic elsewhere cannot corrupt an entry.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::*;
    use crate::{Describe, Res};

    /// A loopback connection inside this process: `(client address, proxy
    /// port, both ends)`.
    fn connection() -> Res<(SocketAddr, u16, (TcpStream, TcpStream))> {
        let listener = TcpListener::bind("127.0.0.1:0").describe()?;
        let port = listener.local_addr().describe()?.port();
        let client = TcpStream::connect(("127.0.0.1", port)).describe()?;
        let addr = client.local_addr().describe()?;
        let (accepted, _) = listener.accept().describe()?;
        Ok((addr, port, (client, accepted)))
    }

    fn own_exe() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_lowercase()))
            .unwrap_or_default()
    }

    #[test]
    fn names_the_program_on_the_client_end_of_a_connection() -> Res<()> {
        let (client, port, _ends) = connection()?;
        let origin = Origin::new(port);
        let exe = origin.exe_for_client(client);
        assert_eq!(exe.as_deref(), Some(own_exe().as_str()));
        assert!(
            std::path::Path::new(&own_exe())
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe")),
            "{}",
            own_exe()
        );
        Ok(())
    }

    #[test]
    fn unknown_connections_have_no_owner() -> Res<()> {
        let (_, port, _ends) = connection()?;
        let origin = Origin::new(port);
        // Nothing was ever connected from this port.
        let nobody: SocketAddr = "127.0.0.1:9".parse().describe()?;
        assert_eq!(origin.exe_for_client(nobody), None);
        Ok(())
    }

    #[test]
    fn the_remote_end_must_be_the_proxy_port() -> Res<()> {
        let (client, port, _ends) = connection()?;
        // Same client address, but the proxy listens somewhere else.
        let other = Origin::new(port.wrapping_add(1));
        assert_eq!(other.exe_for_client(client), None);
        Ok(())
    }

    #[test]
    fn owners_are_remembered_for_ten_seconds() -> Res<()> {
        let (client, port, ends) = connection()?;
        let origin = Origin::new(port);
        let t0 = Instant::now();
        let exe = origin.exe_at(t0, client);
        assert_eq!(exe.as_deref(), Some(own_exe().as_str()));
        drop(ends);

        // Plant a wrong owner (pid 4, the System process) to see which
        // answers come from the cache and which from a fresh scan.
        lock(&origin.owners).insert(client, (4, t0));
        let cached = origin.exe_at(t0 + Duration::from_secs(5), client);
        assert_eq!(cached.as_deref(), Some("system"), "inside the TTL: cached");
        Ok(())
    }

    #[test]
    fn stale_owners_are_scanned_again() -> Res<()> {
        let (client, port, _ends) = connection()?;
        let origin = Origin::new(port);
        let t0 = Instant::now();
        lock(&origin.owners).insert(client, (4, t0));
        let fresh = origin.exe_at(t0 + Duration::from_secs(11), client);
        assert_eq!(
            fresh.as_deref(),
            Some(own_exe().as_str()),
            "past the TTL: rescanned"
        );
        // The rescan replaced the stale entry.
        let replaced = lock(&origin.owners).get(&client).map(|&(pid, _)| pid);
        assert_eq!(replaced, Some(std::process::id()));
        Ok(())
    }

    #[test]
    fn exe_names_are_remembered_for_ten_seconds() {
        let origin = Origin::new(1);
        let t0 = Instant::now();
        let own = std::process::id();
        let name = origin.name_of(t0, own);
        assert_eq!(name.as_deref(), Some(own_exe().as_str()));
        // A process id is reused by another program once its process has ended: what is
        // remembered for it must not outlive the connections that asked.
        lock(&origin.names).insert(own, (Arc::from("stale.exe"), t0));
        assert_eq!(
            origin.name_of(t0 + Duration::from_secs(9), own).as_deref(),
            Some("stale.exe")
        );
        assert_eq!(
            origin.name_of(t0 + Duration::from_secs(11), own).as_deref(),
            Some(own_exe().as_str())
        );
    }

    #[test]
    fn a_missing_process_has_no_name() {
        let origin = Origin::new(1);
        assert_eq!(origin.name_of(Instant::now(), u32::MAX - 1), None);
    }
}
