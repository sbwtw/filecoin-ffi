use reqwest::blocking::{Client, RequestBuilder};

lazy_static! {
    static ref REQWEST_CLIENT: Client = Client::new();
}

pub(crate) fn create_post(path: &str) -> RequestBuilder {
    REQWEST_CLIENT.post(&format!("http://10.61.10.231:8888/{}", path))
}

macro_rules! post_builder {
    ($path:literal) => {
        crate::util::rpc::create_post($path)
    };
}
