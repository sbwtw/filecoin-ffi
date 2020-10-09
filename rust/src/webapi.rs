use crate::proofs::types::*;
use crate::scheduler::*;
use crate::scheduler_grpc::SchedulerClient;
use crate::util::api::init_log;
use ffi_toolkit::{catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus};
use filecoin_proofs_api::seal::SealCommitPhase2Output;
use filecoin_proofs_api::SectorId;
use filecoin_webapi::polling::PollingState;
use filecoin_webapi::*;
use futures::executor;
use grpc::{ClientStubExt, RequestOptions};
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
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{env, mem, thread};

static REQWEST_CLIENT: Lazy<Client> = Lazy::new(|| {
    let mut builder = ClientBuilder::new();
    for config in CONFIG.servers.iter() {
        let mut buf = vec![];
        fs::File::open(&config.cert)
            .expect("open cert file failed!")
            .read_to_end(&mut buf)
            .expect("read cert file failed");
        let cert = Certificate::from_pem(&buf).expect("read PEM cert failed");
        builder = builder.add_root_certificate(cert);
    }

    builder.build().expect("Build Reqwest client failed!")
});

static CONFIG: Lazy<WebApiConfig> = Lazy::new(|| {
    let f = fs::File::open("/etc/filecoin-ffi.yaml").expect("open config file failed");
    let config = serde_yaml::from_reader(f).unwrap();

    info!("filecoin-webapi config: {:?}", config);
    config
});

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ServerConfig {
    url: String,
    cert: String,
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

/*=== gRpc implements ===*/
#[macro_export]
macro_rules! wait_cond {
    ($cond:expr, $poll_time:expr, $keep_live_time:expr) => {{
        grpc_request($cond, $poll_time, $keep_live_time)
    }};
}

fn grpc_request<S: AsRef<str>>(cond: S, poll_time: u64, keep_live_time: u64) -> LiveGuard {
    let client: SchedulerClient =
        SchedulerClient::new_plain("127.0.0.1", 3000, Default::default()).unwrap();

    let req_name = format!(
        "{}-{}",
        cond.as_ref(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut req = AccessResource::new();
    req.set_request_resource(cond.as_ref().to_owned());
    req.set_name(req_name.clone());

    let (client, token) = loop {
        let f = client
            .try_access(RequestOptions::new(), req.clone())
            .join_metadata_result();
        let r = executor::block_on(f).expect("grpc req error").1;
        if r.has_token() {
            debug!("{} got token {}", &req_name, r.get_token().get_token());
            break (Arc::new(client), Arc::new((r.get_token()).clone()));
        }

        thread::sleep(Duration::from_secs(poll_time));
    };

    LiveGuard::new(client, token, keep_live_time)
}

pub struct LiveGuard {
    client: Arc<SchedulerClient>,
    ping_token: Arc<ResourceToken>,
    thread_handle: Option<thread::JoinHandle<()>>,
    thread_exit_sender: Sender<()>,
}

impl LiveGuard {
    #[allow(dead_code)]
    fn new(
        client: Arc<SchedulerClient>,
        token: Arc<ResourceToken>,
        keep_live_timeout: u64,
    ) -> Self {
        let (tx, rx) = channel();
        let mut guard = Self {
            client: client.clone(),
            ping_token: token.clone(),
            thread_handle: None,
            thread_exit_sender: tx,
        };

        let handle = thread::spawn(move || loop {
            match rx.try_recv() {
                Ok(_) => {
                    debug!("LiveGuard {} destroyed", token.get_token());
                    break;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    warn!("recv error");
                    break;
                }
            }

            thread::sleep(Duration::from_secs(keep_live_timeout));
            trace!("rpc ping token {}", token.get_token());
            let f = client
                .ping(RequestOptions::new(), (*token).clone())
                .drop_metadata();

            executor::block_on(f).expect("grpc req error");
        });

        guard.thread_handle = Some(handle);
        guard
    }
}

impl std::ops::Drop for LiveGuard {
    fn drop(&mut self) {
        self.thread_exit_sender.send(()).unwrap();
        self.thread_handle
            .take()
            .unwrap()
            .join()
            .expect("Thread join failed");
        let f = self
            .client
            .remove_guard(RequestOptions::new(), (*self.ping_token).clone())
            .drop_metadata();

        executor::block_on(f).expect("grpc req error");
    }
}

/*=== webapi macros ===*/

// #[allow(dead_code)]
// pub(crate) fn webapi_upload<F: AsRef<str>>(file: F) -> Result<String, String> {
//     let mut f = File::open(file.as_ref()).map_err(|e| format!("{:?}", e))?;
//     let mut buf = vec![];
//     f.read_to_end(&mut buf).map_err(|e| format!("{:?}", e))?;
//
//     let form = Form::new()
//         .file("webapi_upload", file.as_ref())
//         .map_err(|e| format!("{:?}", e))?;
//     let post = REQWEST_CLIENT.post(&format!("{}/sys/upload_file", CONFIG.url));
//     let response = post
//         .multipart(form)
//         .send()
//         .map_err(|e| format!("{:?}", e))?
//         .text()
//         .map_err(|e| format!("{:?}", e))?;
//     let upload_file: Option<String> =
//         serde_json::from_str(&response).map_err(|e| format!("{:?}", e))?;
//
//     upload_file.ok_or("None".to_string())
// }

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
                .map_err(|e| WebApiError::Error(format!("{:?}", e)))?
        }
        Err(e) => return Err(WebApiError::Error(format!("{:?}", e))),
    };

    let value: Value =
        serde_json::from_str(&text).map_err(|e| WebApiError::Error(format!("{:?}", e)))?;
    if value.get("Err").is_some() {
        return Err(WebApiError::Error(format!("{:?}", value)));
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
                trace!("proc_id: {}, Pending...", proc_id);
            }
            e @ _ => {
                debug!("Polling Error: {:?}", e);
                return Err(format!("poll_state error: {:?}", e));
            }
        }

        // sleep 30s
        let time = Duration::from_secs(30);
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

        let _guard = wait_cond!("C2".to_string(), 30, 60);

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
            let r = webapi_post_polling!("seal/seal_commit_phase2", &json_data);
            info!("response: {:?}", r);

            if let Err(e) = r {
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
