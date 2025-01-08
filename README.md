# Trusted proxies

This crate allow you to extract a trusted client ip address, host and port from a http request.

## Usage

```rust
use trusted_proxies::{Config, Trusted};
use http::Request;

fn main() {
    // By default it will trust Forwarded and X-Forwarded-For headers with private ip addresses.
    let config = Config::default();
    let request = Request::get("http://example.com:8080")
        .header("X-Forwarded-For", "1.1.1.1");

    // 192.168.0.1 is the client ip address, which should be extracted from the connection.
    // It is trusted by default as it is a private ip address.
    let trusted = Trusted::extract("192.168.0.1".parse().unwrap(), &config, &request);
    
    assert_eq!(trusted.ip(), "1.1.1.1".parse().unwrap());
    assert_eq!(trusted.host(), "example.com");
    assert_eq!(trusted.port(), 8080);
    assert_eq!(trusted.scheme(), "http");
}
```

## Features

 * Use the `Forwarded` header to extract the client ip address and other informations in priority.
 * Fall back to the `X-Forwarded-For` header if the `Forwarded` header is not present or not trusted.
 * Can extract information from the `X-Forwarded-Host` / `X-Forwarded-Proto` / `X-Forwarded-By` headers if they are trusted.

## Implementation

This crate try to follow the [RFC 7239](https://tools.ietf.org/html/rfc7239) specifications but may differ on real 
world usage.
