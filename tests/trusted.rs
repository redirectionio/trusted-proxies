use http::{HeaderName, HeaderValue};
use rstest::*;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;
use trusted_proxies::{Config, Trusted};

#[derive(Debug, Deserialize)]
struct ConfigJson {
    trusted_ips: Option<Vec<IpAddr>>,
    #[serde(default)]
    empty: bool,
    #[serde(default)]
    is_forwarded_trusted: bool,
    #[serde(default)]
    is_x_forwarded_for_trusted: bool,
    #[serde(default)]
    is_x_forwarded_host_trusted: bool,
    #[serde(default)]
    is_x_forwarded_proto_trusted: bool,
    #[serde(default)]
    is_x_forwarded_by_trusted: bool,
}

#[derive(Debug, Deserialize)]
struct Expected {
    host: Option<String>,
    scheme: Option<String>,
    ip: Option<IpAddr>,
}

#[rstest]
fn fixture(
    #[files("**/*.test")]
    #[base_dir = "tests/fixtures"]
    path: PathBuf,
) {
    let content = std::fs::read_to_string(&path).unwrap();
    let split = content
        .split("-----------------------\n")
        .collect::<Vec<&str>>();

    let ip_addr_str = split.get(0).expect("no ip address");
    let plain_http_request = split.get(1).expect("no plain http request");
    let config_str = split.get(2).expect("no config");
    let expected_str = split.get(3).expect("no expected");

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed_request = httparse::Request::new(&mut headers);

    parsed_request.parse(plain_http_request.as_bytes()).unwrap();

    let mut request = http::Request::new(());
    let mut headers_owned = vec![];

    for header in parsed_request.headers.iter() {
        let name = header.name.to_string();
        let value = std::str::from_utf8(header.value).unwrap().to_string();

        let header_name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        let header_value = HeaderValue::from_bytes(value.as_bytes()).unwrap();

        headers_owned.push((name, value));
        request.headers_mut().append(header_name, header_value);
    }

    *request.version_mut() = match parsed_request.version {
        Some(1) => http::Version::HTTP_11,
        Some(2) => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    };
    *request.method_mut() = match parsed_request.method {
        Some("GET") => http::Method::GET,
        Some("POST") => http::Method::POST,
        Some("PUT") => http::Method::PUT,
        Some("DELETE") => http::Method::DELETE,
        Some("PATCH") => http::Method::PATCH,
        Some("OPTIONS") => http::Method::OPTIONS,
        Some("HEAD") => http::Method::HEAD,
        Some("TRACE") => http::Method::TRACE,
        Some("CONNECT") => http::Method::CONNECT,
        _ => http::Method::GET,
    };
    *request.uri_mut() = match parsed_request.path {
        Some(path) => path.parse().unwrap(),
        _ => "/".parse().unwrap(),
    };

    let ip_addr = ip_addr_str.trim().parse::<IpAddr>().unwrap();
    let config_json = serde_json::from_str::<ConfigJson>(config_str).unwrap();
    let expected =
        serde_json::from_str::<Expected>(expected_str).expect("failed to parse expected");

    let mut config = if config_json.empty {
        Config::new()
    } else {
        Config::new_local()
    };

    if let Some(trusted_ips) = config_json.trusted_ips {
        for trusted_ip in trusted_ips {
            config.add_trusted_ip(&trusted_ip.to_string()).unwrap();
        }
    }

    if config_json.is_forwarded_trusted {
        config.trust_forwarded();
    }

    if config_json.is_x_forwarded_for_trusted {
        config.trust_x_forwarded_for();
    }

    if config_json.is_x_forwarded_host_trusted {
        config.trust_x_forwarded_host();
    }

    if config_json.is_x_forwarded_proto_trusted {
        config.trust_x_forwarded_proto();
    }

    if config_json.is_x_forwarded_by_trusted {
        config.trust_x_forwarded_by();
    }

    let trusted = Trusted::from(ip_addr, &request, &config);

    assert_eq!(trusted.host(), expected.host.as_deref());
    assert_eq!(trusted.scheme(), expected.scheme.as_deref());

    if let Some(ip) = expected.ip {
        assert_eq!(trusted.ip(), ip);
    }
}
