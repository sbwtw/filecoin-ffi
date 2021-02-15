use crate::proofs::types::*;
use crate::util::api::init_log;
use ffi_toolkit::{catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus};
use filecoin_proofs_api::seal::SealCommitPhase2Output;
use filecoin_proofs_api::SectorId;
use filecoin_webapi::polling::PollingState;
use filecoin_webapi::*;
use log::*;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::Certificate;
use serde::{Deserialize, Serialize};
use serde_json::{from_value, json, Value};
use std::fs::{self};
use std::io::Read;
use std::slice::from_raw_parts;
use std::time::Duration;
use std::{env, mem, thread};

static REQWEST_CLIENT: Lazy<Client> = Lazy::new(|| {
    let mut builder = ClientBuilder::new();
    for config in CONFIG.servers.iter() {
        if let Some(cert) = &config.cert {
            let mut buf = vec![];
            fs::File::open(cert)
                .expect("open cert file failed!")
                .read_to_end(&mut buf)
                .expect("read cert file failed");
            let c = Certificate::from_pem(&buf).expect("read PEM cert failed");
            builder = builder.add_root_certificate(c);
        }
    }

    builder.build().expect("Build Reqwest client failed!")
});

// fn reqwest_client() -> Client {
//     let mut builder = ClientBuilder::new();
//     for config in CONFIG.servers.iter() {
//         if let Some(cert) = &config.cert {
//             let mut buf = vec![];
//             fs::File::open(cert)
//                 .expect("open cert file failed!")
//                 .read_to_end(&mut buf)
//                 .expect("read cert file failed");
//             let c = Certificate::from_pem(&buf).expect("read PEM cert failed");
//             builder = builder.add_root_certificate(c);
//         }
//     }
//
//     builder.build().expect("Build Reqwest client failed!")
// }

static CONFIG: Lazy<WebApiConfig> = Lazy::new(|| {
    let location = env::var("FILECOIN_FFI_CONFIG").unwrap_or("/etc/filecoin-ffi.yaml".to_string());
    info!("Use config file: {}", location);
    let f = fs::File::open(location).expect("open config file failed");
    let server_cfg: WebApiConfig = serde_yaml::from_reader(f).unwrap();

    debug!("filecoin-webapi config: {:?}", server_cfg);
    server_cfg
});

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ServerConfig {
    url: String,
    cert: Option<String>,
    token: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct WebApiConfig {
    servers: Vec<ServerConfig>,
}

impl WebApiConfig {
    fn pick_server(&self) -> ServerConfig {
        self.servers
            .choose(&mut rand::thread_rng())
            .expect("No server found!")
            .clone()
    }
}

/*=== webapi macros ===*/
#[derive(Debug)]
enum WebApiError {
    StatusError(u16),
    Error(String),
}

/// pick server to post, if successful, return value and server host
/// path: request resource path
/// json: request data
#[allow(dead_code)]
fn webapi_post_pick<T: Serialize + ?Sized>(
    path: &str,
    json: &T,
) -> Result<(ServerConfig, Value), String> {
    loop {
        let server = CONFIG.pick_server();
        let url = format!("{}{}", server.url, path);
        match webapi_post(&url, &server.token, json) {
            Ok(val) => return Ok((server.clone(), val)),
            Err(WebApiError::Error(err)) => return Err(err),
            Err(WebApiError::StatusError(stat)) => {
                debug!("status error: {}", stat);

                // TooManyRequests
                if stat != 429 {
                    return Err(format!("Err with code: {}", stat));
                }
            }
        }

        // sleep
        debug!("TooManyRequests in server {:?}, waiting...", server);
        thread::sleep(Duration::from_secs(60));
    }
}

#[allow(dead_code)]
fn webapi_post<T: Serialize + ?Sized>(
    url: &str,
    token: &str,
    json: &T,
) -> Result<Value, WebApiError> {
    trace!("webapi_post url: {}", url);

    let post = REQWEST_CLIENT.post(url).header("Authorization", token);
    let text = match post.json(json).send() {
        Ok(response) => {
            let stat = response.status().as_u16();
            if stat != 200 {
                return Err(WebApiError::StatusError(stat));
            }

            response
                .text()
                .map_err(|e| WebApiError::Error(format!("webapi_post response error: {:?}", e)))?
        }
        Err(e) => return Err(WebApiError::Error(format!("webapi_post error: {:?}", e))),
    };

    let value: Value = serde_json::from_str(&text)
        .map_err(|e| WebApiError::Error(format!("webapi_post parse error: {:?}", e)))?;
    if value.get("Err").is_some() {
        return Err(WebApiError::Error(format!(
            "webapi_post remote return error: {:?}",
            value
        )));
    }

    return Ok(value);
}

#[allow(dead_code)]
pub(crate) fn webapi_post_polling<T: Serialize + ?Sized>(
    path: &str,
    json: &T,
) -> Result<Value, String> {
    let (server, state) = match webapi_post_pick(path, json) {
        Ok((server, value)) => {
            let state: PollingState = from_value(value).map_err(|e| format!("{:?}", e))?;
            (server, state)
        }
        Err(e) => return Err(e),
    };

    info!(
        "webapi_post_polling request server: {:?}, state: {:?}",
        server, state
    );

    let proc_id = match state {
        PollingState::Started(val) => val,
        e @ _ => {
            return Err(format!("webapi_post_polling response error: {:?}", e));
        }
    };

    loop {
        let url = format!("{}{}", server.url, "sys/query_state");
        let val =
            webapi_post(&url, &server.token, &json!(proc_id)).map_err(|e| format!("{:?}", e))?;
        let poll_state: PollingState = from_value(val).map_err(|e| format!("{:?}", e))?;

        match poll_state {
            PollingState::Done(result) => return Ok(result),
            PollingState::Pending => {
                debug!("proc_id: {}, Pending...", proc_id);
            }
            e @ _ => {
                warn!("Polling Error: {:?}", e);
                return Err(format!("poll_state error: {:?}", e));
            }
        }

        // sleep 60s
        trace!("sleep 60s");
        let time = Duration::from_secs(60);
        thread::sleep(time);
    }
}

// #[allow(unused_macros)]
// macro_rules! webapi_post {
//     ($path:literal, $json:expr) => {
//         crate::util::rpc::webapi_post($path, $json);
//     };
// }

#[allow(unused_macros)]
macro_rules! webapi_post_polling {
    ($path:literal, $json:expr) => {
        crate::webapi::webapi_post_polling($path, $json);
    };
}

/*=== Interface reimplements ===*/
#[no_mangle]
pub(crate) unsafe fn fil_seal_commit_phase2_webapi(
    seal_commit_phase1_output_ptr: *const u8,
    seal_commit_phase1_output_len: libc::size_t,
    sector_id: u64,
    prover_id: fil_32ByteArray,
) -> *mut fil_SealCommitPhase2Response {
    catch_panic_response(|| {
        init_log();

        info!("seal_commit_phase2: start");

        let mut response = fil_SealCommitPhase2Response::default();

        let scp1o = serde_json::from_slice(from_raw_parts(
            seal_commit_phase1_output_ptr,
            seal_commit_phase1_output_len,
        ))
        .map_err(Into::into);

        if env::var("DISABLE_WEBAPI").is_err() {
            let web_data = seal_data::SealCommitPhase2Data {
                phase1_output: scp1o.unwrap(),
                prover_id: prover_id.inner,
                sector_id: SectorId::from(sector_id),
            };
            let json_data = json!(web_data);
            trace!("webapi_post_polling: start");
            let r = webapi_post_polling!("seal/seal_commit_phase2", &json_data);

            if let Err(e) = r {
                trace!("response: {:?}", &e);
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", e));
                return raw_ptr(response);
            }

            let r = r.unwrap();
            let output: SealCommitPhase2Output =
                serde_json::from_value(r.get("Ok").unwrap().clone()).unwrap();
            response.status_code = FCPResponseStatus::FCPNoError;
            response.proof_ptr = output.proof.as_ptr();
            response.proof_len = output.proof.len();
            mem::forget(output.proof);
        } else {
            let result = scp1o.and_then(|o| {
                filecoin_proofs_api::seal::seal_commit_phase2(
                    o,
                    prover_id.inner,
                    SectorId::from(sector_id),
                )
            });

            match result {
                Ok(output) => {
                    response.status_code = FCPResponseStatus::FCPNoError;
                    response.proof_ptr = output.proof.as_ptr();
                    response.proof_len = output.proof.len();
                    mem::forget(output.proof);
                }
                Err(err) => {
                    response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                    response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                }
            }
        }

        info!("seal_commit_phase2: finish");

        raw_ptr(response)
    })
}
