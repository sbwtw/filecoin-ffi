use reqwest::blocking::{Client, RequestBuilder};

lazy_static! {
    static ref REQWEST_CLIENT: Client = Client::new();
}

static HOST: &str = "127.0.0.1:8888";
// static HOST: &str = "111.44.254.130:44694";

pub(crate) fn create_post(path: &str) -> RequestBuilder {
    REQWEST_CLIENT.post(&format!("http://{}/{}", HOST, path))
}

macro_rules! post_builder {
    ($path:literal) => {
        crate::util::rpc::create_post($path)
    };
}
