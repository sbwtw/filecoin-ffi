use reqwest::blocking::{Client, RequestBuilder};
use serde::ser::Serialize;
use serde_json::Value;

lazy_static! {
    static ref REQWEST_CLIENT: Client = Client::new();
}

static HOST: &str = "127.0.0.1:8888";
// static HOST: &str = "111.44.254.130:44694";

// pub(crate) fn create_post(path: &str) -> RequestBuilder {
//     REQWEST_CLIENT.post(&format!("http://{}/{}", HOST, path))
// }

pub(crate) fn webapi_post<T: Serialize + ?Sized>(path: &str, json: &T) -> Result<Value, String> {
    let post = REQWEST_CLIENT.post(&format!("http://{}/{}", HOST, path));
    let response = post
        .json(json)
        .send()
        .map_err(|e| format!("{:?}", e))?
        .text()
        .map_err(|e| format!("{:?}", e))?;
    let value: Value = serde_json::from_str(&response).map_err(|e| format!("{:?}", e))?;

    if value.get("Err").is_some() {
        return Err(format!("{:?}", value));
    }

    return Ok(value);
}

// macro_rules! post_builder {
//     ($path:literal) => {
//         crate::util::rpc::create_post($path)
//     };
// }

macro_rules! webapi_post {
    ($path:literal, $json:expr) => {
        crate::util::rpc::webapi_post($path, $json);
    };
}
