//! # Trusted proxies
//!
//! This crate allow you to extract a trusted client ip address, host and port from a http request.
//!
//! ## Usage
//!
//! ```rust
//! use trusted_proxies::{Config, Trusted};
//! use http::Request;
//!
//! let config = Config::new_local();
//! let mut request = http::Request::get("/").body(()).unwrap();
//! request.headers_mut().insert(http::header::FORWARDED, "for=1.2.3.4; proto=https; by=myproxy; host=mydomain.com:8080".parse().unwrap());
//! let socket_ip_addr = core::net::IpAddr::from([127, 0, 0, 1]);
//!
//! let trusted = Trusted::from(socket_ip_addr, &request, &config);
//!
//! assert_eq!(trusted.scheme(), Some("https"));
//! assert_eq!(trusted.host(), Some("mydomain.com"));
//! assert_eq!(trusted.port(), Some(8080));
//! assert_eq!(trusted.ip(), core::net::IpAddr::from([1, 2, 3, 4]));
//! ```
//!
//! ## Features
//!
//!  * Use the `Forwarded` header to extract the client ip address and other informations in priority.
//!  * Fall back to the `X-Forwarded-For` header if the `Forwarded` header is not present or not trusted.
//!  * Can extract information from the `X-Forwarded-Host` / `X-Forwarded-Proto` / `X-Forwarded-By` headers if they are trusted.
//!
//! ## Implementation
//!
//! This crate try to follow the [RFC 7239](https://tools.ietf.org/html/rfc7239) specifications but may differ on real
//! world usage.

mod config;
mod extract;
mod trusted;

pub use config::Config;
pub use extract::RequestInformation;
pub use trusted::Trusted;
