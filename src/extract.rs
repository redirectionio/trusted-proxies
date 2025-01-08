pub trait RequestInformation {
    fn is_host_header_allowed(&self) -> bool;

    fn host_header(&self) -> Option<&str>;

    fn scheme(&self) -> Option<&str>;

    fn authority(&self) -> Option<&str>;

    fn forwarded(&self) -> impl DoubleEndedIterator<Item = &str>;

    fn x_forwarded_for(&self) -> impl DoubleEndedIterator<Item = &str>;

    fn x_forwarded_host(&self) -> impl DoubleEndedIterator<Item = &str>;

    fn x_forwarded_proto(&self) -> impl DoubleEndedIterator<Item = &str>;

    fn x_forwarded_by(&self) -> impl DoubleEndedIterator<Item = &str>;

    fn default_host(&self) -> Option<&str> {
        self.host_header()
            // skip host header if HTTP/2, we should use :authority instead
            .filter(|_| self.is_host_header_allowed())
            .or_else(|| self.authority())
    }

    fn default_scheme(&self) -> Option<&str> {
        self.scheme()
    }
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

        fn scheme(&self) -> Option<&str> {
            self.uri().scheme_str()
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

        fn scheme(&self) -> Option<&str> {
            self.uri.scheme_str()
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
    }
}
