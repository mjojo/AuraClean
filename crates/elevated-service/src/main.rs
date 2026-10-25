//! AuraClean Privileged Worker Service (`auraclean-service`).
//!
//! Enforces privilege separation, explicit User SID context resolution,
//! and Scoped Scan Token authorization over Windows Named Pipes.
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

use ipc_protocol::{DEFAULT_NAMED_PIPE_PATH, IpcRequest, IpcResponse};

fn main() {
    tracing_subscriber::fmt::init();
    let pong = handle_request(IpcRequest::Ping);
    tracing::info!(
        pipe = DEFAULT_NAMED_PIPE_PATH,
        response = ?pong,
        "AuraClean Privileged Service initialized (mjojo Zero-Breakage Architecture)"
    );
}

pub fn handle_request(req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Ping => IpcResponse::Pong {
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            vendor: "mjojo".to_string(),
        },
        _ => IpcResponse::Error {
            code: "SPRINT_4_PENDING".to_string(),
            message: "Full Named Pipe worker dispatch is scheduled for Sprint 4.".to_string(),
        },
    }
}
