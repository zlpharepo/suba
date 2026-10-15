use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

/// How the public server is addressed and where it keeps its files.
pub struct ServerConfig {
    /// Address the listener binds to.
    pub listen: ListenAddr,
    pub port: u16,
    /// Directory holding the configuration files.
    pub config_dir: PathBuf,
    /// Directory holding runtime data, such as sessions and the web UI.
    pub data_dir: PathBuf,
    /// What the command line said about running with a privilege.
    ///
    /// A core that creates an interface needs root, so an instance that serves
    /// such a configuration is started as root on purpose. A run that is root
    /// without this is refused: nothing should end up as root by accident, and
    /// a root run has to be told whose files it is holding.
    pub privileged: crate::identity::Privileged,
}

/// The address of the public listener.
///
/// The host is parsed once, when it is provided, so a malformed address can
/// never reach [`tokio::net::TcpListener::bind`].
pub struct ListenAddr {
    host: String,
    ip: IpAddr,
}

impl ListenAddr {
    /// The parsed IP the listener binds to.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The host as it was provided, for display.
    pub fn host(&self) -> &str {
        &self.host
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host)
    }
}

impl FromStr for ListenAddr {
    type Err = std::net::AddrParseError;

    fn from_str(host: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            host: host.to_owned(),
            ip: host.parse()?,
        })
    }
}

impl ServerConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen.ip(), self.port)
    }
}
