/// A trait to extract required information from a request in order to fetch trusted information
pub trait RequestInformation {
    /// Check if the host header is allowed
    ///
    /// Most implementations should return `true` if the HTTP version is less than HTTP/2
    fn is_host_header_allowed(&self) -> bool;

    /// Get the host header of the request
    fn host_header(&self) -> Option<&str>;

    /// Get the authority of the request
    fn authority(&self) -> Option<&str>;

    /// Get the `Forwarded` header values
    ///
    /// A double-ended iterator is returned to allow the implementation to optimize the iteration in
    /// case of multiple values
    fn forwarded(&self) -> impl DoubleEndedIterator<Item = &str>;

    /// Get the `X-Forwarded-For` header values
    fn x_forwarded_for(&self) -> impl DoubleEndedIterator<Item = &str>;

    /// Get the `X-Forwarded-Host` header values
    fn x_forwarded_host(&self) -> impl DoubleEndedIterator<Item = &str>;

    /// Get the `X-Forwarded-Proto` header values
    fn x_forwarded_proto(&self) -> impl DoubleEndedIterator<Item = &str>;

    /// Get the `X-Forwarded-By` header values
    fn x_forwarded_by(&self) -> impl DoubleEndedIterator<Item = &str>;

    /// Return the default host of the request when no trusted headers are found
    ///
    /// Default to host header if allowed or authority
    fn default_host(&self) -> Option<&str> {
        self.host_header()
            // skip host header if HTTP/2, we should use :authority instead
            .filter(|_| self.is_host_header_allowed())
            .or_else(|| self.authority())
    }

    /// Return the default scheme of the request when no trusted headers are found
    fn default_scheme(&self) -> Option<&str>;
}

#[cfg(feature = "http")]
mod http {
    use super::RequestInformation;

    impl<T> RequestInformation for http::Request<T> {
        fn is_host_header_allowed(&self) -> bool {
            self.version() < http::Version::HTTP_2
        }

        fn host_header(&self) -> Option<&str> {
            self.headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
        }

        fn authority(&self) -> Option<&str> {
            self.uri().authority().map(|auth| auth.as_str())
        }

        fn forwarded(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers()
                .get_all("forwarded")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_for(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers()
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_host(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers()
                .get_all("x-forwarded-host")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_proto(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers()
                .get_all("x-forwarded-proto")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_by(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers()
                .get_all("x-forwarded-by")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn default_scheme(&self) -> Option<&str> {
            self.uri().scheme_str()
        }
    }

    impl RequestInformation for http::request::Parts {
        fn is_host_header_allowed(&self) -> bool {
            self.version < http::Version::HTTP_2
        }

        fn host_header(&self) -> Option<&str> {
            self.headers
                .get("host")
                .and_then(|value| value.to_str().ok())
        }

        fn authority(&self) -> Option<&str> {
            self.uri.authority().map(|auth| auth.as_str())
        }

        fn forwarded(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers
                .get_all("forwarded")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_for(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_host(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers
                .get_all("x-forwarded-host")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_proto(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers
                .get_all("x-forwarded-proto")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn x_forwarded_by(&self) -> impl DoubleEndedIterator<Item = &str> {
            self.headers
                .get_all("x-forwarded-by")
                .iter()
                .filter_map(|value| value.to_str().ok())
        }

        fn default_scheme(&self) -> Option<&str> {
            self.uri.scheme_str()
        }
    }
}
