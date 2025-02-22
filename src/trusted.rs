use crate::extract::RequestInformation;
use crate::Config;
use core::net::IpAddr;

/// Trusted data extracted from a request
///
/// Values returned by this struct are trusted and can be used to determine the real client information,
/// given your configuration.
///
/// # Example
/// ```
/// use trusted_proxies::{Config, Trusted};
///
/// let config = Config::new_local();
/// let mut request = http::Request::get("/").body(()).unwrap();
/// request.headers_mut().insert(http::header::FORWARDED, "for=1.2.3.4; proto=https; by=myproxy; host=mydomain.com:8080".parse().unwrap());
/// let socket_ip_addr = core::net::IpAddr::from([127, 0, 0, 1]);
///
/// let trusted = Trusted::from(socket_ip_addr, &request, &config);
///
/// assert_eq!(trusted.scheme(), Some("https"));
/// assert_eq!(trusted.host(), Some("mydomain.com"));
/// assert_eq!(trusted.port(), Some(8080));
/// assert_eq!(trusted.ip(), core::net::IpAddr::from([1, 2, 3, 4]));
/// ```
#[derive(Debug, Clone)]
pub enum Trusted<'a> {
    Borrowed(TrustedBorrowed<'a>),
    Owned(TrustedOwned),
}

#[derive(Debug, Clone)]
pub struct TrustedBorrowed<'a> {
    host: Option<&'a str>,
    scheme: Option<&'a str>,
    by: Option<&'a str>,
    ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct TrustedOwned {
    host: Option<String>,
    scheme: Option<String>,
    by: Option<String>,
    ip: IpAddr,
}

/// Trim whitespace then any quote marks.
fn unquote(val: &str) -> &str {
    val.trim().trim_start_matches('"').trim_end_matches('"')
}

/// Remove port and IPv6 square brackets from a peer specification.
fn bare_address(val: &str) -> &str {
    if val.starts_with('[') {
        val.split("]:")
            .next()
            .map(|s| s.trim_start_matches('[').trim_end_matches(']'))
            // this indicates that the IPv6 address is malformed so shouldn't
            // usually happen, but if it does, just return the original input
            .unwrap_or(val)
    } else {
        val.split(':').next().unwrap_or(val)
    }
}

impl Trusted<'_> {
    pub fn into_owned(self) -> Trusted<'static> {
        match self {
            Self::Borrowed(trusted) => Trusted::Owned(TrustedOwned {
                host: trusted.host.map(|s| s.to_string()),
                scheme: trusted.scheme.map(|s| s.to_string()),
                by: trusted.by.map(|s| s.to_string()),
                ip: trusted.ip,
            }),
            Self::Owned(trusted) => Trusted::Owned(trusted),
        }
    }
}

impl<'a> Trusted<'a> {
    /// Get the scheme of the request
    pub fn scheme(&self) -> Option<&str> {
        match self {
            Self::Borrowed(trusted) => trusted.scheme,
            Self::Owned(trusted) => trusted.scheme.as_deref(),
        }
    }

    /// Get the host and potential port of the request
    pub fn host_with_port(&self) -> Option<&str> {
        match self {
            Self::Borrowed(trusted) => trusted.host,
            Self::Owned(trusted) => trusted.host.as_deref(),
        }
    }

    /// Get the host of the request (without port)
    pub fn host(&self) -> Option<&str> {
        self.host_with_port()
            .and_then(|host| host.split(':').next())
    }

    /// Get the port of the request
    pub fn port(&self) -> Option<u16> {
        self.host_with_port().and_then(|host| {
            host.split(':')
                .nth(1)
                .and_then(|port| port.parse::<u16>().ok())
        })
    }

    /// Get the proxy that forwarded the request
    pub fn by(&self) -> Option<&str> {
        match self {
            Self::Borrowed(trusted) => trusted.by,
            Self::Owned(trusted) => trusted.by.as_deref(),
        }
    }

    /// Get first untrusted IP address from the request, which should be in most cases the real client IP address
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Borrowed(trusted) => trusted.ip,
            Self::Owned(trusted) => trusted.ip,
        }
    }

    /// Create a new `Trusted` struct from a peer address, a request and a configuration
    pub fn from<T: RequestInformation>(ip_addr: IpAddr, request: &'a T, config: &Config) -> Self {
        let (trusted_host, trusted_scheme, trusted_by, trusted_ip) =
            if !config.is_ip_trusted(&ip_addr) {
                // if the peer address is not trusted, we can't trust the headers
                // set the host and scheme to the server's configuration
                (
                    request.default_host(),
                    request.default_scheme(),
                    None,
                    ip_addr,
                )
            } else {
                // if the peer address is trusted, we can start to check trusted header to get correct information
                let mut host = None;
                let mut scheme = None;
                let mut by = None;
                let mut realip_remote_addr = None;

                // first check the forwarded header if it is trusted
                if config.is_forwarded_trusted {
                    // quote from RFC 7239:
                    // A proxy server that wants to add a new "Forwarded" header field value
                    //    can either append it to the last existing "Forwarded" header field
                    //    after a comma separator or add a new field at the end of the header
                    //    block.
                    // --- https://datatracker.ietf.org/doc/html/rfc7239#section-4
                    // so we get the values in reverse order as we want to get the first untrusted value
                    let forwarded_list = request
                        .forwarded()
                        // "for=1.2.3.4, for=5.6.7.8; scheme=https"
                        .flat_map(|vals| vals.split(','))
                        // ["for=1.2.3.4", "for=5.6.7.8; scheme=https"]
                        .rev();

                    'forwaded: for forwarded in forwarded_list {
                        for (key, value) in forwarded.split(';').map(|item| {
                            let mut kv = item.splitn(2, '=');

                            (
                                kv.next().map(|s| s.trim()).unwrap_or_default(),
                                kv.next().map(|s| unquote(s.trim())).unwrap_or_default(),
                            )
                        }) {
                            match key.to_lowercase().as_str() {
                                "for" => {
                                    if let Ok(ip) = bare_address(value).parse::<IpAddr>() {
                                        realip_remote_addr = Some(ip);

                                        if config.is_ip_trusted(&ip) {
                                            host = None;
                                            scheme = None;
                                            by = None;
                                            realip_remote_addr = None;

                                            continue 'forwaded;
                                        }
                                    }
                                }
                                "proto" => {
                                    scheme = Some(value);
                                }
                                "host" => {
                                    host = Some(value);
                                }
                                "by" => {
                                    by = Some(value);
                                }
                                _ => {}
                            }
                        }

                        break;
                    }
                }

                if realip_remote_addr.is_none() && config.is_x_forwarded_for_trusted {
                    for value in request
                        .x_forwarded_for()
                        .flat_map(|vals| vals.split(','))
                        .map(|s| s.trim())
                        .rev()
                    {
                        if let Ok(ip) = bare_address(value).parse::<IpAddr>() {
                            if config.is_ip_trusted(&ip) {
                                continue;
                            }

                            realip_remote_addr = Some(ip);
                        }

                        break;
                    }
                }

                if host.is_none() && config.is_x_forwarded_host_trusted {
                    host = request
                        .x_forwarded_host()
                        .flat_map(|vals| vals.split(','))
                        .map(|s| s.trim())
                        .next_back();
                }

                if scheme.is_none() && config.is_x_forwarded_proto_trusted {
                    scheme = request
                        .x_forwarded_proto()
                        .flat_map(|vals| vals.split(','))
                        .map(|s| s.trim())
                        .next_back();
                }

                if by.is_none() && config.is_x_forwarded_by_trusted {
                    by = request
                        .x_forwarded_by()
                        .flat_map(|vals| vals.split(','))
                        .map(|s| s.trim())
                        .next_back();
                }

                (
                    host.or_else(|| request.default_host()),
                    scheme.or_else(|| request.default_scheme()),
                    by,
                    realip_remote_addr.unwrap_or(ip_addr),
                )
            };

        Self::Borrowed(TrustedBorrowed {
            host: trusted_host,
            scheme: trusted_scheme,
            by: trusted_by,
            ip: trusted_ip,
        })
    }
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::*;
    use http::{header, Request, Version};

    #[test]
    fn default() {
        let request = Request::get("http://localhost:8080/").body(()).unwrap();
        let config = Config::default();
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("http"));
        assert_eq!(trusted.host(), Some("localhost"));
        assert_eq!(trusted.port(), Some(8080));
        assert_eq!(trusted.ip(), "127.0.0.1".parse::<IpAddr>().unwrap())
    }

    #[test]
    fn host_header() {
        let mut request = Request::get("http://localhost:8080/").body(()).unwrap();
        request
            .headers_mut()
            .insert(header::HOST, "rust-lang.org:8081".parse().unwrap());
        let config = Config::default();
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("http"));
        assert_eq!(trusted.host(), Some("rust-lang.org"));
        assert_eq!(trusted.port(), Some(8081));
        assert_eq!(trusted.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn host_header_not_allowed() {
        let mut request = Request::get("http://localhost:8080/").body(()).unwrap();
        request
            .headers_mut()
            .insert(header::HOST, "rust-lang.org".parse().unwrap());
        *request.version_mut() = Version::HTTP_2;
        let config = Config::default();
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("http"));
        assert_eq!(trusted.host(), Some("localhost"));
        assert_eq!(trusted.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_forwarded_for_header_trusted() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().insert(
            header::HeaderName::from_static("x-forwarded-for"),
            "1.1.1.1".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_forwarded_for_header_trusted_multiple() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "1.1.1.1".parse().unwrap(),
        );
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "8.8.8.8".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "8.8.8.8".parse::<IpAddr>().unwrap());

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "1.1.1.1".parse().unwrap(),
        );
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "8.8.8.8".parse().unwrap(),
        );

        let mut config = Config::default();
        config
            .add_trusted_ip("8.8.8.8")
            .expect("Failed to add trusted ip");

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "1.1.1.1, 8.8.8.8".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "8.8.8.8".parse::<IpAddr>().unwrap());

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "1.1.1.1, 8.8.8.8".parse().unwrap(),
        );

        let mut config = Config::default();
        config
            .add_trusted_ip("8.8.8.8")
            .expect("Failed to add trusted ip");

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_forwarded_for_header_untrusted() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-for"),
            "8.8.8.8".parse().unwrap(),
        );

        let mut config = Config::new();
        config
            .add_trusted_ip("8.8.8.8")
            .expect("Failed to add trusted ip");

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "192.168.2.60".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_forwarded_host_header_trusted() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-host"),
            "example.com:8080".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_host();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.host(), Some("example.com"));
        assert_eq!(trusted.port(), Some(8080));

        let mut request = Request::get("/").body(()).unwrap();
        // In this cas we have multiple hosts, so we should take the last one
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-host"),
            "first.com:1234, example.com".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_host();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.host(), Some("example.com"));
        assert_eq!(trusted.port(), None);

        let mut request = Request::get("/").body(()).unwrap();
        // In this cas we have multiple hosts, so we should take the last one
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-host"),
            "first.com, example.com".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_host();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("1.1.1.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.host(), None);
    }

    #[test]
    fn x_forwarded_host_header_untrusted() {
        let mut request = Request::get("/").body(()).unwrap();
        // In this cas we have multiple hosts, so we should take the last one
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-host"),
            "first.com, example.com".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.host(), None);
    }

    #[test]
    fn x_forwarded_proto_header_trusted() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-proto"),
            "https".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_proto();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("https"));

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-proto"),
            "http".parse().unwrap(),
        );
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-proto"),
            "https".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_proto();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("https"));

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-proto"),
            "http, https".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_proto();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("192.168.2.60".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("https"));

        let mut request = Request::get("/").body(()).unwrap();
        // In this cas we have multiple hosts, so we should take the last one
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-proto"),
            "https".parse().unwrap(),
        );

        let mut config = Config::default();
        config.trust_x_forwarded_proto();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("1.1.1.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), None);
    }

    #[test]
    fn x_forwarded_proto_header_untrusted() {
        let mut request = Request::get("/").body(()).unwrap();
        // In this cas we have multiple hosts, so we should take the last one
        request.headers_mut().append(
            header::HeaderName::from_static("x-forwarded-proto"),
            "https".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), None);
    }

    #[test]
    fn forwarded_header() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            "for=192.0.2.60; proto=https; by=203.0.113.43; host=rust-lang.org"
                .parse()
                .unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.scheme(), Some("https"));
        assert_eq!(trusted.host(), Some("rust-lang.org"));
        assert_eq!(trusted.by(), Some("203.0.113.43"));
        assert_eq!(trusted.ip(), "192.0.2.60".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_case_sensitivity() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            "For=192.0.2.60".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);

        assert_eq!(trusted.ip(), "192.0.2.60".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_for_quoted() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            r#"for="192.0.2.60:8080""#.parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);
        assert_eq!(trusted.ip(), "192.0.2.60".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_for_ipv6() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            r#"for="[2001:db8:cafe::17]""#.parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);
        assert_eq!(trusted.ip(), "2001:db8:cafe::17".parse::<IpAddr>().unwrap());
        assert!(trusted.ip().is_ipv6());
    }

    #[test]
    fn forwarded_for_ipv6_with_port() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            r#"for="[2001:db8:cafe::17]:4711""#.parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);
        assert_eq!(trusted.ip(), "2001:db8:cafe::17".parse::<IpAddr>().unwrap());
        assert!(trusted.ip().is_ipv6());
    }

    #[test]
    fn forwarded_for_multiple() {
        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            "for=192.0.2.60, for=198.51.100.17".parse().unwrap(),
        );

        let config = Config::default();

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);
        assert_eq!(trusted.ip(), "198.51.100.17".parse::<IpAddr>().unwrap());

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            "for=192.0.2.60;proto=https, for=198.51.100.17;proto=http"
                .parse()
                .unwrap(),
        );

        let mut config = Config::default();
        config
            .add_trusted_ip("198.51.100.17")
            .expect("Failed to add trusted ip");

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);
        assert_eq!(trusted.ip(), "192.0.2.60".parse::<IpAddr>().unwrap());
        assert_eq!(trusted.scheme(), Some("https"));

        let mut request = Request::get("/").body(()).unwrap();
        request.headers_mut().append(
            header::HeaderName::from_static("forwarded"),
            "for=192.0.2.60, for=198.51.100.17;proto=http"
                .parse()
                .unwrap(),
        );

        let mut config = Config::default();
        config
            .add_trusted_ip("198.51.100.17")
            .expect("Failed to add trusted ip");

        // 192.168.2.60 is a local ip address, so it should be trusted by default
        let trusted = Trusted::from("127.0.0.1".parse().unwrap(), &request, &config);
        assert_eq!(trusted.ip(), "192.0.2.60".parse::<IpAddr>().unwrap());
        assert_eq!(trusted.scheme(), None);
    }
}
