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

#[cfg(unix)]
#[test]
fn both_listeners_start_and_sigterm_stops_them() {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        process::Stdio,
        time::{Duration, Instant},
    };
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut process = ChildGuard(
        command()
            .args([
                "serve",
                "--admin-bind",
                "127.0.0.1:0",
                "--public-bind",
                "127.0.0.1:0",
                "--data-dir",
            ])
            .arg(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = process.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut lines = String::new();
        for _ in 0..3 {
            reader.read_line(&mut lines).unwrap();
        }
        let _ = tx.send(lines);
    });
    let lines = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("startup deadline");
    assert!(lines.contains("Console: http://127.0.0.1:"));
    assert!(lines.contains("Public API: http://127.0.0.1:"));
    let public = lines
        .lines()
        .find(|line| line.starts_with("Public API: "))
        .unwrap()
        .trim_start_matches("Public API: http://")
        .split(' ')
        .next()
        .unwrap();
    let mut socket = std::net::TcpStream::connect(public).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        socket,
        "GET /health HTTP/1.1\r\nHost: {public}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let token = fs::read_to_string(dir.path().join("admin.token")).unwrap();
    assert!(!lines.contains(&token));
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "shutdown deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}
