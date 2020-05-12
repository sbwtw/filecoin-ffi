use reqwest::blocking::{Client, RequestBuilder};

lazy_static! {
    static ref REQWEST_CLIENT: Client = Client::new();
}

pub(crate) fn create_post(path: &str) -> RequestBuilder {
    REQWEST_CLIENT.post(&format!("http://111.44.254.130:44694/{}", path))
}

macro_rules! post_builder {
    ($path:literal) => {
        crate::util::rpc::create_post($path)
    };
}
