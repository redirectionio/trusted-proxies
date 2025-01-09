use core::net::IpAddr;

use ipnet::{AddrParseError, IpNet};

/// Config for trusted proxies extractor
///
/// By default, it trusts the following:
///   - IPV4 Loopback
///   - IPV4 Private Networks
///   - IPV6 Loopback
///   - IPV6 Private Networks
///
/// It also trusts the `Forwarded` and `X-Forwarded-For` header by default.
///
/// # Example
/// ```
/// use trusted_proxies::Config;
///
/// let mut config = Config::new_local();
/// config.add_trusted_ip("168.10.0.0/16").unwrap();
/// config.trust_x_forwarded_host();
///
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    trusted_ips: Vec<IpNet>,
    pub(crate) is_forwarded_trusted: bool,
    pub(crate) is_x_forwarded_for_trusted: bool,
    pub(crate) is_x_forwarded_host_trusted: bool,
    pub(crate) is_x_forwarded_proto_trusted: bool,
    pub(crate) is_x_forwarded_by_trusted: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::new_local()
    }
}

impl Config {
    /// Create a new TrustedProxies instance with no trusted proxies or headers
    pub fn new() -> Self {
        Self {
            trusted_ips: Vec::new(),
            is_forwarded_trusted: false,
            is_x_forwarded_for_trusted: false,
            is_x_forwarded_host_trusted: false,
            is_x_forwarded_proto_trusted: false,
            is_x_forwarded_by_trusted: false,
        }
    }

    /// Create a new TrustedProxies instance with local and private networks ip trusted and FORWARDED / X-Forwarded-For headers trusted
    pub fn new_local() -> Self {
        Self {
            trusted_ips: vec![
                // IPV4 Loopback
                "127.0.0.0/8".parse().unwrap(),
                // IPV4 Private Networks
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                // IPV6 Loopback
                "::1/128".parse().unwrap(),
                // IPV6 Private network
                "fd00::/8".parse().unwrap(),
            ],
            is_forwarded_trusted: true,
            is_x_forwarded_for_trusted: true,
            is_x_forwarded_host_trusted: false,
            is_x_forwarded_proto_trusted: false,
            is_x_forwarded_by_trusted: false,
        }
    }

    /// Add a trusted proxy to the list of trusted proxies
    ///
    /// proxy can be an IP address or a CIDR
    pub fn add_trusted_ip(&mut self, proxy: &str) -> Result<(), AddrParseError> {
        match proxy.parse() {
            Ok(v) => {
                self.trusted_ips.push(v);

                Ok(())
            }
            Err(e) => match proxy.parse::<IpAddr>() {
                Ok(v) => {
                    self.trusted_ips.push(IpNet::from(v));

                    Ok(())
                }
                _ => Err(e),
            },
        }
    }

    /// Check if a remote address is trusted given the list of trusted proxies
    pub fn is_ip_trusted(&self, remote_addr: &IpAddr) -> bool {
        for proxy in &self.trusted_ips {
            if proxy.contains(remote_addr) {
                return true;
            }
        }

        false
    }

    /// Trust the `Forwarded` header
    pub fn trust_forwarded(&mut self) {
        self.is_forwarded_trusted = true;
    }

    /// Trust the `X-Forwarded-For` header
    pub fn trust_x_forwarded_for(&mut self) {
        self.is_x_forwarded_for_trusted = true;
    }

    /// Trust the `X-Forwarded-Host` header to fetch the host and optionally the port
    ///
    /// It is not recommended to trust this header as it can be easily spoofed, however you can trust
    /// it if you are behind a reverse proxy that **always** sets this header.
    ///
    /// If there is multiple values in the header, the last one is used, even if there is multiple
    /// proxies in the chain.
    ///
    /// If you need to get the original value with multiple proxies in the chain, you can use the
    /// `Forwarded` header that allows to do that in a secure way.
    /// See [RFC7239](https://tools.ietf.org/html/rfc7239) for more information.
    pub fn trust_x_forwarded_host(&mut self) {
        self.is_x_forwarded_host_trusted = true;
    }

    /// Trust the `X-Forwarded-Proto` header to fetch the scheme
    ///
    /// It is not recommended to trust this header as it can be easily spoofed, however you can trust
    /// it if you are behind a reverse proxy that **always** sets this header.
    ///
    /// If there is multiple values in the header, the last one is used, even if there is multiple
    /// proxies in the chain.
    ///
    /// If you need to get the original value with multiple proxies in the chain, you can use the
    /// `Forwarded` header that allows to do that in a secure way.
    /// See [RFC7239](https://tools.ietf.org/html/rfc7239) for more information.
    pub fn trust_x_forwarded_proto(&mut self) {
        self.is_x_forwarded_proto_trusted = true;
    }

    /// Trust the `X-Forwarded-By` header to identify the proxy that sent the request
    ///
    /// It is not recommended to trust this header as it can be easily spoofed, however you can trust
    /// it if you are behind a reverse proxy that **always** sets this header.
    ///
    /// If there is multiple values in the header, the last one is used, even if there is multiple
    /// proxies in the chain.
    ///
    /// If you need to get the original value with multiple proxies in the chain, you can use the
    /// `Forwarded` header that allows to do that in a secure way.
    /// See [RFC7239](https://tools.ietf.org/html/rfc7239) for more information.
    pub fn trust_x_forwarded_by(&mut self) {
        self.is_x_forwarded_by_trusted = true;
    }
}
