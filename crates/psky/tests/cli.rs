//! Black-box CLI regression tests. They never contact public services.

use std::{fs, process::Command};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_psky"))
}

#[test]
fn lab_cli_emits_evidence_and_refuses_overwrite() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("experiment");
    let run = || {
        command()
            .args(["lab", "--output"])
            .arg(&path)
            .output()
            .unwrap()
    };
    let first = run();
    assert!(first.status.success());
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["network_proof"], false);
    assert_eq!(report["exports_checked"], 4);
    let original = fs::read(path.join("worker-a/rev-1.car")).unwrap();
    let second = run();
    assert!(!second.status.success());
    assert_eq!(fs::read(path.join("worker-a/rev-1.car")).unwrap(), original);
}

#[test]
fn invalid_network_and_missing_endpoints_fail_before_requests() {
    assert!(
        !command()
            .args(["preflight", "--network", "wrong"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let result = command().arg("preflight").output().unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("configure between 1 and 8 endpoints")
    );
}

#[test]
fn credential_url_is_rejected_without_echoing_secret() {
    let result = command()
        .args([
            "preflight",
            "--endpoint",
            "https://user:SECRET_MARKER@example.com",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("SECRET_MARKER"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("SECRET_MARKER"));
}

#[test]
fn public_admin_bind_fails_without_creating_state() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("unused");
    let result = command()
        .args(["serve", "--admin-bind", "0.0.0.0:8788", "--data-dir"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!path.exists());
}

#[test]
fn admin_token_unknown_directory_does_not_initialize_state() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("uninitialized");
    let result = command()
        .args(["admin-token", "--data-dir"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!path.exists());
}

#[test]
fn admin_token_prints_existing_token_without_modifying_or_logging_it() {
    let directory = tempfile::tempdir().unwrap();
    let token = psky::server::load_admin_token(directory.path()).unwrap();
    let original = fs::read(directory.path().join("admin.token")).unwrap();
    let result = command()
        .args(["admin-token", "--data-dir"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).trim() == token);
    assert!(!String::from_utf8_lossy(&result.stderr).contains(&token));
    assert!(fs::read(directory.path().join("admin.token")).unwrap() == original);
    assert!(!directory.path().join("settings.json").exists());
}

#[cfg(unix)]
mod live_node {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{SocketAddr, TcpStream},
        path::Path,
        process::{Command, Stdio},
        sync::{Arc, Mutex, mpsc},
        time::{Duration, Instant},
    };

    use serde_json::Value;

    use super::command;

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct Capture {
        bytes: Arc<Mutex<Vec<u8>>>,
        done: mpsc::Receiver<()>,
    }

    impl Capture {
        fn new(reader: impl Read + Send + 'static, startup: Option<mpsc::Sender<String>>) -> Self {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&bytes);
            let (done_tx, done) = mpsc::channel();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(reader);
                loop {
                    let mut line = Vec::new();
                    match reader.read_until(b'\n', &mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            captured.lock().unwrap().extend_from_slice(&line);
                            if let Some(sender) = &startup {
                                let _ = sender.send(String::from_utf8_lossy(&line).into_owned());
                            }
                        }
                    }
                }
                let _ = done_tx.send(());
            });
            Self { bytes, done }
        }

        fn assert_finished_without(&self, token: &str) {
            self.done
                .recv_timeout(Duration::from_secs(2))
                .expect("output capture deadline");
            assert!(!String::from_utf8_lossy(&self.bytes.lock().unwrap()).contains(token));
        }
    }

    pub(super) struct Node {
        process: ChildGuard,
        pub(super) admin: SocketAddr,
        pub(super) public: SocketAddr,
        stdout: Capture,
        stderr: Capture,
    }

    impl Node {
        pub(super) fn start(directory: &Path, arguments: &[&str]) -> Self {
            let mut process = ChildGuard(
                command()
                    .args(["serve", "--data-dir"])
                    .arg(directory)
                    .args(arguments)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let (startup_tx, startup_rx) = mpsc::channel();
            let stdout = Capture::new(process.0.stdout.take().unwrap(), None);
            let stderr = Capture::new(process.0.stderr.take().unwrap(), Some(startup_tx));
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut admin = None;
            let mut public = None;
            while admin.is_none() || public.is_none() {
                let line = startup_rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("node startup deadline");
                if let Some(address) = line.strip_prefix("Console: http://") {
                    admin = Some(address.trim().parse().unwrap());
                }
                if let Some(address) = line.strip_prefix("Public API: http://") {
                    public = Some(address.split_whitespace().next().unwrap().parse().unwrap());
                }
            }
            Self {
                process,
                admin: admin.unwrap(),
                public: public.unwrap(),
                stdout,
                stderr,
            }
        }

        pub(super) fn admin_json(
            &self,
            token: &str,
            method: &str,
            path: &str,
            body: Option<&Value>,
        ) -> Value {
            let encoded = body.map_or_else(Vec::new, |body| serde_json::to_vec(body).unwrap());
            let (status, response) = request(self.admin, method, path, Some(token), &encoded);
            assert_eq!(status, 200, "management request failed");
            serde_json::from_slice(&response).unwrap()
        }

        pub(super) fn stop(mut self, token: &str) {
            assert!(
                Command::new("kill")
                    .args(["-TERM", &self.process.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = self.process.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "node shutdown deadline");
                std::thread::sleep(Duration::from_millis(10));
            }
            self.stdout.assert_finished_without(token);
            self.stderr.assert_finished_without(token);
        }
    }

    pub(super) fn request(
        address: SocketAddr,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(socket, "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len()).unwrap();
        if let Some(token) = token {
            write!(socket, "Authorization: Bearer {token}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        socket.write_all(body).unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        let boundary = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&response[..boundary]);
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, response[boundary + 4..].to_vec())
    }
}

#[cfg(unix)]
#[test]
fn both_listeners_start_and_sigterm_stops_them() {
    let directory = tempfile::tempdir().unwrap();
    let node = live_node::Node::start(
        directory.path(),
        &[
            "--admin-bind",
            "127.0.0.1:0",
            "--public-bind",
            "127.0.0.1:0",
        ],
    );
    assert!(node.admin.ip().is_loopback());
    assert!(node.public.ip().is_loopback());
    let (status, body) = live_node::request(node.public, "GET", "/health", None, &[]);
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["pds_ready"],
        false
    );
    let token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
    node.stop(&token);
}

#[cfg(unix)]
#[test]
fn api_configuration_survives_process_restart_and_wins_over_bootstrap_flags() {
    use serde_json::json;

    let directory = tempfile::tempdir().unwrap();
    let first = live_node::Node::start(
        directory.path(),
        &[
            "--admin-bind",
            "127.0.0.1:0",
            "--public-bind",
            "127.0.0.1:0",
        ],
    );
    let token = fs::read_to_string(directory.path().join("admin.token")).unwrap();
    let original = first.admin_json(&token, "GET", "/admin/config", None);
    let original_status = first.admin_json(&token, "GET", "/admin/status", None);
    let mut settings = original["settings"].clone();
    settings["node_name"] = json!("Configured through the API");
    settings["endpoints"] = json!(["http://127.0.0.1:3381"]);
    settings["network"] = json!("testnet");
    settings["test_fid"] = json!(8531);
    settings["request_timeout_ms"] = json!(7234);
    settings["max_response_bytes"] = json!(65536);
    settings["max_block_delay_seconds"] = json!(120);
    settings["serve_fixture"] = json!(true);
    let fixture_path = format!(
        "/xrpc/com.atproto.sync.getRepo?did={}",
        psky::lab::FIXTURE_DID
    );
    assert_eq!(
        live_node::request(first.public, "GET", &fixture_path, None, &[]).0,
        503
    );
    let saved = first.admin_json(
        &token,
        "PUT",
        "/admin/config",
        Some(&json!({"expected_revision":original["revision"],"settings":settings})),
    );
    assert_eq!(saved["revision"], 2);
    assert_eq!(saved["settings"], settings);
    assert_eq!(
        live_node::request(first.public, "GET", &fixture_path, None, &[]).0,
        200
    );
    first.stop(&token);

    // Even an invalid first-start admin address must not overwrite a valid
    // saved document. No configured endpoint is contacted by this test.
    let restarted = live_node::Node::start(
        directory.path(),
        &[
            "--admin-bind",
            "0.0.0.0:8788",
            "--public-bind",
            "127.0.0.1:8787",
            "--network",
            "devnet",
            "--fid",
            "999",
            "--endpoint",
            "http://127.0.0.1:3382",
        ],
    );
    let current = restarted.admin_json(&token, "GET", "/admin/config", None);
    let status = restarted.admin_json(&token, "GET", "/admin/status", None);
    assert_eq!(current["revision"], saved["revision"]);
    assert_eq!(current["settings"], settings);
    assert_eq!(current["restart_required"], false);
    assert_eq!(
        current["active_listeners"]["admin_bind"],
        restarted.admin.to_string()
    );
    assert_eq!(
        current["active_listeners"]["public_bind"],
        restarted.public.to_string()
    );
    assert_ne!(status["instance_id"], original_status["instance_id"]);
    assert_eq!(status["node_name"], settings["node_name"]);
    assert_eq!(status["preflight"], serde_json::Value::Null);
    assert_eq!(
        live_node::request(restarted.public, "GET", &fixture_path, None, &[]).0,
        200
    );
    let token_command = command()
        .args(["admin-token", "--data-dir"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(token_command.status.success());
    assert!(String::from_utf8_lossy(&token_command.stdout).trim() == token);
    assert!(!String::from_utf8_lossy(&token_command.stderr).contains(&token));
    restarted.stop(&token);
}
