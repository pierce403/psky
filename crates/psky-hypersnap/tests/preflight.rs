//! HTTP fixtures exercise request boundaries without writing to any network.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use psky_hypersnap::{
    Compatibility, DEFAULT_MAX_BLOCK_DELAY_SECS, DEFAULT_MAX_RESPONSE_BYTES, Failure, Freshness,
    MAX_BLOCK_DELAY_SECS, MAX_ENDPOINTS, MAX_RESPONSE_BYTES, Network, PreflightClient,
    PreflightConfig,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

// Older or incomplete responses must remain compatible without becoming healthy.
const INFO: &str = r#"{"version":"0.13.5","numShards":2,"dbStats":{"numMessages":123}}"#;
const SECRET: &str = "TOP_SECRET_AUTH_TOKEN";

struct Reply {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
    header_delay: Duration,
    body_delay: Duration,
    chunked: bool,
}

impl Reply {
    fn json(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            headers: Vec::new(),
            header_delay: Duration::ZERO,
            body_delay: Duration::ZERO,
            chunked: false,
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::json(SECRET)
        }
    }
}

struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl MockServer {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                while !request.ends_with(b"\r\n\r\n") {
                    let count = stream.read(&mut buf).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..count]);
                    assert!(request.len() <= 8192);
                }
                observed
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                tokio::time::sleep(reply.header_delay).await;
                let mut headers = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nConnection: close\r\n",
                    reply.status
                );
                if reply.chunked {
                    headers.push_str("Transfer-Encoding: chunked\r\n");
                } else {
                    headers.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
                }
                for (name, value) in reply.headers {
                    headers.push_str(&format!("{name}: {value}\r\n"));
                }
                headers.push_str("\r\n");
                if stream.write_all(headers.as_bytes()).await.is_err() {
                    continue;
                }
                tokio::time::sleep(reply.body_delay).await;
                if reply.chunked {
                    for chunk in reply.body.as_bytes().chunks(17) {
                        if stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await
                            .is_err()
                            || stream.write_all(chunk).await.is_err()
                            || stream.write_all(b"\r\n").await.is_err()
                        {
                            break;
                        }
                    }
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                } else {
                    let _ = stream.write_all(reply.body.as_bytes()).await;
                }
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(endpoint: &str, fid: Option<u64>) -> PreflightConfig {
    PreflightConfig::new(vec![endpoint.to_owned()], Network::Mainnet, fid).unwrap()
}

fn cast(network: Value, fid: u64) -> String {
    json!({"messages":[{"data":{"fid":fid,"network":network,"castAddBody":{"text":SECRET}}}]})
        .to_string()
}

fn allocation() -> String {
    json!({"units":4,"limits":[{"name":"CASTS","limit":20000,"used":4813}]}).to_string()
}

fn registry(fid: u64) -> String {
    json!({"events":[{
        "fid":fid,"blockNumber":30,"txIndex":1,"logIndex":4,
        "idRegisterEventBody":{"eventType":"Transfer","to":"0x1111111111111111111111111111111111111111"}
    },{
        "fid":fid,"blockNumber":20,"txIndex":1,"logIndex":4,
        "idRegisterEventBody":{"eventType":"Register","to":"0x2222222222222222222222222222222222222222"}
    }]}).to_string()
}

fn compatible_replies(network: Value) -> Vec<Reply> {
    vec![
        Reply::json(INFO),
        Reply::json(cast(network, 8531)),
        Reply::json(allocation()),
        Reply::json(registry(8531)),
    ]
}

fn info(peer_id: &str, block_delay: u64) -> Value {
    json!({
        "version":"0.13.5","numShards":2,"dbStats":{"numMessages":123},
        "peer_id":peer_id,
        "shardInfos":[
            {"shardId":0,"maxHeight":100,"blockDelay":0,"numMessages":2},
            {"shardId":1,"maxHeight":200,"blockDelay":block_delay,"numMessages":60},
            {"shardId":2,"maxHeight":150,"blockDelay":1}
        ]
    })
}

fn replies_with_info(info: Value) -> Vec<Reply> {
    let mut replies = compatible_replies(json!(1));
    replies[0] = Reply::json(info.to_string());
    replies
}

#[test]
fn network_names_are_explicit_and_round_trip() {
    for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
        assert_eq!(network.to_string().parse::<Network>().unwrap(), network);
        let serialized = serde_json::to_string(&network).unwrap();
        assert_eq!(
            serde_json::from_str::<Network>(&serialized).unwrap(),
            network
        );
    }
    assert!("MAINNET".parse::<Network>().is_err());
    let error = SECRET.parse::<Network>().unwrap_err();
    assert!(!error.to_string().contains(SECRET));
}

#[test]
fn config_requires_bounded_distinct_endpoints_and_nonzero_fid() {
    assert!(PreflightConfig::new(vec![], Network::Mainnet, None).is_err());
    assert!(
        PreflightConfig::new(
            vec!["https://example.com".into(); MAX_ENDPOINTS + 1],
            Network::Mainnet,
            None
        )
        .is_err()
    );
    assert!(
        PreflightConfig::new(
            vec![
                "https://example.com".into(),
                "https://example.com:443/".into()
            ],
            Network::Mainnet,
            None
        )
        .is_err()
    );
    assert!(
        PreflightConfig::new(
            vec!["https://example.com".into()],
            Network::Mainnet,
            Some(0)
        )
        .is_err()
    );
    let endpoints = (0..MAX_ENDPOINTS)
        .map(|i| format!("https://node{i}.example.com"))
        .collect();
    assert!(PreflightConfig::new(endpoints, Network::Mainnet, None).is_ok());
}

#[test]
fn config_accepts_https_and_only_loopback_plain_http() {
    for endpoint in [
        "https://example.com",
        "http://127.0.0.1:8080",
        "http://127.0.1.2",
        "http://[::1]:8080",
        "http://localhost:8080",
    ] {
        assert!(
            PreflightConfig::new(vec![endpoint.into()], Network::Mainnet, None).is_ok(),
            "{endpoint}"
        );
    }
    for endpoint in [
        "http://example.com",
        "http://192.168.1.3",
        "http://0.0.0.0",
        "http://localhost.example.com",
        "http://[::]",
        "ftp://example.com",
        "file:///tmp/file",
        "junk",
    ] {
        assert!(
            PreflightConfig::new(vec![endpoint.into()], Network::Mainnet, None).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn credential_and_ambiguous_urls_are_rejected_without_echo() {
    for endpoint in [
        format!("https://user:{SECRET}@example.com"),
        format!("https://{SECRET}@example.com"),
        format!("https://example.com/?api_key={SECRET}"),
        format!("https://example.com/#{SECRET}"),
        format!("https://example.com/{SECRET}"),
        SECRET.to_owned(),
    ] {
        let error = PreflightConfig::new(vec![endpoint], Network::Mainnet, None).unwrap_err();
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
    }
}

#[test]
fn limits_are_bounded() {
    for timeout in [
        Duration::ZERO,
        Duration::from_millis(9),
        Duration::from_secs(31),
    ] {
        assert!(
            config("https://example.com", None)
                .with_limits(timeout, 1)
                .is_err()
        );
    }
    for size in [0, MAX_RESPONSE_BYTES + 1] {
        assert!(
            config("https://example.com", None)
                .with_limits(Duration::from_secs(1), size)
                .is_err()
        );
    }
    assert!(
        config("https://example.com", None)
            .with_limits(Duration::from_millis(10), 1)
            .is_ok()
    );
    assert!(
        config("https://example.com", None)
            .with_limits(Duration::from_secs(30), MAX_RESPONSE_BYTES)
            .is_ok()
    );
}

#[test]
fn freshness_threshold_is_bounded() {
    for delay in [0, MAX_BLOCK_DELAY_SECS + 1, u64::MAX] {
        assert!(
            config("https://example.com", None)
                .with_max_block_delay_secs(delay)
                .is_err()
        );
    }
    for delay in [1, DEFAULT_MAX_BLOCK_DELAY_SECS, MAX_BLOCK_DELAY_SECS] {
        assert!(
            config("https://example.com", None)
                .with_max_block_delay_secs(delay)
                .is_ok()
        );
    }
}

#[tokio::test]
async fn info_without_test_fid_does_not_invent_network_evidence() {
    let server = MockServer::start(vec![Reply::json(INFO)]).await;
    let report = PreflightClient::new(config(&server.url, None))
        .unwrap()
        .run()
        .await;
    assert!(!report.compatible);
    assert!(!report.healthy);
    assert_eq!(report.max_block_delay_seconds, DEFAULT_MAX_BLOCK_DELAY_SECS);
    assert!(!report.ready_for_reconstruction);
    assert_eq!(report.nodes[0].protocol, Compatibility::Compatible);
    assert_eq!(report.nodes[0].network, Compatibility::Unknown);
    assert!(report.nodes[0].reachable);
    assert_eq!(report.nodes[0].freshness, Freshness::Unknown);
    assert_eq!(
        report.nodes[0].info.as_ref().unwrap().num_messages,
        Some(123)
    );
    assert_eq!(server.requests().len(), 1);
    assert!(server.requests()[0].starts_with("GET /v1/info HTTP/1.1\r\n"));
}

#[tokio::test]
async fn compatible_nodes_report_only_the_evidence_they_provided() {
    let first = MockServer::start(compatible_replies(json!("FARCASTER_NETWORK_MAINNET"))).await;
    let second = MockServer::start(compatible_replies(json!(1))).await;
    let configured = PreflightConfig::new(
        vec![first.url.clone(), second.url.clone()],
        Network::Mainnet,
        Some(8531),
    )
    .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert!(report.compatible);
    assert!(!report.healthy);
    assert_eq!(report.distinct_peer_count, 0);
    assert!(!report.ready_for_reconstruction);
    assert_eq!(report.nodes.len(), 2);
    assert!(!report.limitations.is_empty());
    for node in &report.nodes {
        assert!(!node.healthy);
        assert_eq!(node.freshness, Freshness::Unknown);
        assert_eq!(node.peer_unique, None);
        assert_eq!(node.observed_network, Some(Network::Mainnet));
        assert!(
            node.requests
                .iter()
                .all(|request| request.failure.is_none())
        );
        assert_eq!(node.storage.as_ref().unwrap().units, 4);
        assert_eq!(node.storage.as_ref().unwrap().limits[0].used, 4813);
        let authority = node.authority.as_ref().unwrap();
        assert!(!authority.verified);
        assert_eq!(authority.registry_events, 2);
        assert_eq!(
            authority.reported_custody.as_deref(),
            Some("0x1111111111111111111111111111111111111111")
        );
    }
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(!encoded.contains(SECRET));
    assert_eq!(report, serde_json::from_str(&encoded).unwrap());
    for server in [&first, &second] {
        let requests = server.requests();
        assert_eq!(requests.len(), 4);
        assert!(requests[1].starts_with("GET /v1/castsByFid?fid=8531&pageSize=1 HTTP/1.1"));
        assert!(requests[2].starts_with("GET /v1/storageLimitsByFid?fid=8531 HTTP/1.1"));
        assert!(requests[3].starts_with(
            "GET /v1/onChainEventsByFid?fid=8531&event_type=EVENT_TYPE_ID_REGISTER HTTP/1.1"
        ));
        for request in requests {
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            assert!(request.starts_with("GET "));
        }
    }
}

#[tokio::test]
async fn fresh_distinct_nodes_pass_health_without_claiming_reconstruction() {
    let first = MockServer::start(replies_with_info(info("12D3KooWNodeA", 30))).await;
    let mut second_info = info("12D3KooWNodeB", 0);
    // Heights differ between nodes because requests are sequential. Freshness
    // compares reported timestamps, not equal heights or hashes.
    second_info["shardInfos"][1]["maxHeight"] = json!(201);
    second_info["shardInfos"].as_array_mut().unwrap().reverse();
    let second = MockServer::start(replies_with_info(second_info)).await;
    let configured = PreflightConfig::new(
        vec![first.url.clone(), second.url.clone()],
        Network::Mainnet,
        Some(8531),
    )
    .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert!(report.compatible);
    assert!(report.healthy);
    assert_eq!(report.distinct_peer_count, 2);
    assert!(!report.ready_for_reconstruction);
    for node in &report.nodes {
        assert!(node.healthy);
        assert_eq!(node.freshness, Freshness::Fresh);
        assert_eq!(node.peer_unique, Some(true));
        let shards = &node.info.as_ref().unwrap().shard_infos;
        assert_eq!(
            shards
                .iter()
                .map(|shard| shard.shard_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(shards[0].num_messages, Some(2));
        assert_eq!(shards[2].num_messages, None);
    }
    assert_eq!(
        report.nodes[0].info.as_ref().unwrap().shard_infos[1].block_delay_seconds,
        30
    );
    let encoded = serde_json::to_string(&report).unwrap();
    assert_eq!(report, serde_json::from_str(&encoded).unwrap());
}

#[tokio::test]
async fn high_block_delay_is_lagging_even_for_a_compatible_endpoint() {
    for block_delay in [31, 19 * 24 * 60 * 60, u64::MAX] {
        let server = MockServer::start(replies_with_info(info("12D3KooWNodeA", block_delay))).await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(report.compatible);
        assert!(!report.healthy);
        assert_eq!(report.nodes[0].freshness, Freshness::Lagging);
        assert!(!report.ready_for_reconstruction);
    }
}

#[tokio::test]
async fn custom_block_delay_threshold_is_used_and_reported() {
    let server = MockServer::start(replies_with_info(info("12D3KooWNodeA", 31))).await;
    let configured = config(&server.url, Some(8531))
        .with_max_block_delay_secs(31)
        .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert!(report.healthy);
    assert_eq!(report.max_block_delay_seconds, 31);
    assert_eq!(report.nodes[0].freshness, Freshness::Fresh);
}

#[tokio::test]
async fn duplicate_peers_never_count_as_two_healthy_nodes() {
    let first = MockServer::start(replies_with_info(info("12D3KooWNodeA", 1))).await;
    let second = MockServer::start(replies_with_info(info("12D3KooWNodeA", 1))).await;
    let configured = PreflightConfig::new(
        vec![first.url.clone(), second.url.clone()],
        Network::Mainnet,
        Some(8531),
    )
    .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert!(report.compatible);
    assert!(!report.healthy);
    assert_eq!(report.distinct_peer_count, 1);
    assert!(
        report
            .nodes
            .iter()
            .all(|node| node.peer_unique == Some(false))
    );
    assert!(report.nodes.iter().all(|node| !node.healthy));
}

#[tokio::test]
async fn missing_peer_identity_keeps_uniqueness_unknown_for_every_node() {
    let first = MockServer::start(replies_with_info(info("12D3KooWNodeA", 1))).await;
    let mut unknown = info("12D3KooWNodeB", 1);
    unknown.as_object_mut().unwrap().remove("peer_id");
    let second = MockServer::start(replies_with_info(unknown)).await;
    let configured = PreflightConfig::new(
        vec![first.url.clone(), second.url.clone()],
        Network::Mainnet,
        Some(8531),
    )
    .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert!(report.compatible);
    assert!(!report.healthy);
    assert_eq!(report.distinct_peer_count, 1);
    assert!(report.nodes.iter().all(|node| node.peer_unique.is_none()));
}

#[tokio::test]
async fn missing_partial_or_empty_shard_data_never_looks_fresh() {
    let complete = info("12D3KooWNodeA", 1);
    let mut absent = complete.clone();
    absent.as_object_mut().unwrap().remove("shardInfos");
    let mut empty = complete.clone();
    empty["shardInfos"] = json!([]);
    let mut partial = complete.clone();
    partial["shardInfos"].as_array_mut().unwrap().pop();
    let mut zero_height = complete;
    zero_height["shardInfos"][0]["maxHeight"] = json!(0);
    for body in [absent, empty, partial, zero_height] {
        let server = MockServer::start(replies_with_info(body)).await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(report.compatible);
        assert!(!report.healthy);
        assert_eq!(report.nodes[0].freshness, Freshness::Unknown);
    }
}

#[tokio::test]
async fn malformed_shard_fields_and_peer_ids_are_rejected() {
    let complete = info("12D3KooWNodeA", 1);
    let mut bad_values = Vec::new();
    for peer in [
        json!(""),
        json!(null),
        json!(123),
        json!("x".repeat(129)),
        json!("<script>alert(1)</script>"),
        json!("peer\nname"),
        json!("péer"),
    ] {
        let mut value = complete.clone();
        value["peer_id"] = peer;
        bad_values.push(value);
    }
    for (field, wrong) in [
        ("shardId", json!(u64::MAX)),
        ("shardId", json!(3)),
        ("maxHeight", json!(-1)),
        ("maxHeight", json!("123")),
        ("blockDelay", json!(-1)),
        ("blockDelay", json!(0.5)),
        ("blockDelay", json!(null)),
        ("numMessages", json!("123")),
    ] {
        let mut value = complete.clone();
        value["shardInfos"][0][field] = wrong;
        bad_values.push(value);
    }
    let mut duplicate = complete.clone();
    duplicate["shardInfos"][1]["shardId"] = json!(0);
    bad_values.push(duplicate);
    let mut missing_delay = complete.clone();
    missing_delay["shardInfos"][0]
        .as_object_mut()
        .unwrap()
        .remove("blockDelay");
    bad_values.push(missing_delay);
    for wrong_shards in [
        json!(null),
        json!({}),
        json!([{}]),
        json!(vec![json!({}); 257]),
    ] {
        let mut value = complete.clone();
        value["shardInfos"] = wrong_shards;
        bad_values.push(value);
    }
    for value in bad_values {
        let server = MockServer::start(vec![Reply::json(value.to_string())]).await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(report.nodes[0].reachable);
        assert!(report.nodes[0].info.is_none(), "{value}");
        assert_eq!(
            report.nodes[0].requests[0].failure,
            Some(Failure::Malformed),
            "{value}"
        );
        assert!(!report.healthy);
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn fresh_unique_wrong_network_is_not_healthy() {
    let mut replies = replies_with_info(info("12D3KooWNodeA", 1));
    replies[1] = Reply::json(cast(json!(2), 8531));
    let server = MockServer::start(replies).await;
    let report = PreflightClient::new(config(&server.url, Some(8531)))
        .unwrap()
        .run()
        .await;
    assert_eq!(report.nodes[0].freshness, Freshness::Fresh);
    assert_eq!(report.nodes[0].peer_unique, Some(true));
    assert_eq!(report.nodes[0].network, Compatibility::Incompatible);
    assert!(!report.healthy);
}

#[tokio::test]
async fn wrong_network_does_not_silently_fail_over() {
    let first = MockServer::start(compatible_replies(json!(1))).await;
    let second = MockServer::start(compatible_replies(json!(2))).await;
    let configured = PreflightConfig::new(
        vec![first.url.clone(), second.url.clone()],
        Network::Mainnet,
        Some(8531),
    )
    .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert!(!report.compatible);
    assert_eq!(report.nodes[0].network, Compatibility::Compatible);
    assert_eq!(report.nodes[1].network, Compatibility::Incompatible);
    assert_eq!(report.nodes[1].observed_network, Some(Network::Testnet));
}

#[tokio::test]
async fn unexpected_version_is_explicitly_incompatible() {
    let server = MockServer::start(vec![Reply::json(INFO.replace("0.13.5", "0.14.0"))]).await;
    let report = PreflightClient::new(config(&server.url, None))
        .unwrap()
        .run()
        .await;
    assert!(!report.compatible);
    assert_eq!(report.nodes[0].protocol, Compatibility::Incompatible);
    assert_eq!(report.nodes[0].info.as_ref().unwrap().version, "0.14.0");
}

#[tokio::test]
async fn malformed_info_is_rejected_before_account_queries() {
    for body in [
        "not JSON",
        "[]",
        "null",
        r#"{"version":"0.13.5"}"#,
        r#"{"version":"0.13.5","numShards":0,"dbStats":{}}"#,
        r#"{"version":"0.13.5","numShards":2,"dbStats":{"numMessages":"123"}}"#,
        r#"{"version":"<script>alert(1)</script>","numShards":2,"dbStats":{}}"#,
    ] {
        let server = MockServer::start(vec![Reply::json(body)]).await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(report.nodes[0].info.is_none(), "{body}");
        assert_eq!(
            report.nodes[0].requests[0].failure,
            Some(Failure::Malformed),
            "{body}"
        );
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn empty_casts_or_unknown_enum_leave_network_unknown() {
    for body in [
        json!({"messages":[]}).to_string(),
        cast(json!(0), 8531),
        cast(json!("FARCASTER_NETWORK_FUTURE"), 8531),
    ] {
        let server = MockServer::start(vec![
            Reply::json(INFO),
            Reply::json(body),
            Reply::status(404),
            Reply::status(404),
        ])
        .await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(!report.compatible);
        assert_eq!(report.nodes[0].network, Compatibility::Unknown);
        assert_eq!(report.nodes[0].requests[1].failure, None);
    }
}

#[tokio::test]
async fn malformed_or_wrong_fid_casts_are_rejected() {
    let two_messages =
        json!({"messages":[{"data":{"fid":8531,"network":1}},{"data":{"fid":8531,"network":1}}]})
            .to_string();
    for body in [
        cast(json!(1), 99),
        json!({"messages":[{}]}).to_string(),
        "{}".into(),
        two_messages,
    ] {
        let server = MockServer::start(vec![
            Reply::json(INFO),
            Reply::json(body),
            Reply::status(404),
            Reply::status(404),
        ])
        .await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(!report.compatible);
        assert_eq!(
            report.nodes[0].requests[1].failure,
            Some(Failure::Malformed)
        );
    }
}

#[tokio::test]
async fn unavailable_optional_routes_keep_their_explicit_unknown_state() {
    let server = MockServer::start(vec![
        Reply::json(INFO),
        Reply::status(404),
        Reply::status(501),
        Reply::status(404),
    ])
    .await;
    let report = PreflightClient::new(config(&server.url, Some(8531)))
        .unwrap()
        .run()
        .await;
    assert!(!report.compatible);
    assert!(report.nodes[0].storage.is_none());
    assert!(report.nodes[0].authority.is_none());
    assert!(
        report.nodes[0].requests[1..]
            .iter()
            .all(|request| request.failure == Some(Failure::Unavailable))
    );
    assert!(!serde_json::to_string(&report).unwrap().contains(SECRET));
}

#[tokio::test]
async fn errors_do_not_retain_response_bodies_headers_or_request_urls() {
    for (status, expected) in [
        (401, Failure::HttpStatus),
        (403, Failure::HttpStatus),
        (404, Failure::Unavailable),
        (429, Failure::HttpStatus),
        (500, Failure::HttpStatus),
        (501, Failure::Unavailable),
    ] {
        let mut reply = Reply::status(status);
        reply
            .headers
            .push(("Set-Cookie".into(), format!("credential={SECRET}")));
        let server = MockServer::start(vec![reply]).await;
        let report = PreflightClient::new(config(&server.url, None))
            .unwrap()
            .run()
            .await;
        assert_eq!(report.nodes[0].requests[0].failure, Some(expected));
        assert_eq!(report.nodes[0].requests[0].status, Some(status));
        assert_eq!(report.nodes[0].requests[0].response_bytes, 0);
        assert!(!serde_json::to_string(&report).unwrap().contains(SECRET));
    }
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let destination = MockServer::start(vec![Reply::json(INFO)]).await;
    for status in [301, 302, 303, 307, 308] {
        let mut reply = Reply::status(status);
        reply.headers.push((
            "Location".into(),
            format!("{}/?token={SECRET}", destination.url),
        ));
        let origin = MockServer::start(vec![reply]).await;
        let report = PreflightClient::new(config(&origin.url, None))
            .unwrap()
            .run()
            .await;
        assert_eq!(report.nodes[0].requests[0].failure, Some(Failure::Redirect));
        assert!(!serde_json::to_string(&report).unwrap().contains(SECRET));
    }
    assert!(destination.requests().is_empty());
}

#[tokio::test]
async fn content_length_over_limit_is_rejected_before_reading_body() {
    let server = MockServer::start(vec![Reply::json(
        "x".repeat(DEFAULT_MAX_RESPONSE_BYTES + 1),
    )])
    .await;
    let report = PreflightClient::new(config(&server.url, None))
        .unwrap()
        .run()
        .await;
    assert_eq!(
        report.nodes[0].requests[0].failure,
        Some(Failure::Oversized)
    );
    assert_eq!(report.nodes[0].requests[0].response_bytes, 0);
}

#[tokio::test]
async fn streamed_body_cap_is_enforced_without_content_length() {
    let mut reply = Reply::json("x".repeat(512));
    reply.chunked = true;
    let server = MockServer::start(vec![reply]).await;
    let configured = config(&server.url, None)
        .with_limits(Duration::from_secs(1), 128)
        .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert_eq!(
        report.nodes[0].requests[0].failure,
        Some(Failure::Oversized)
    );
    assert!(report.nodes[0].requests[0].response_bytes > 128);
}

#[tokio::test]
async fn valid_chunked_json_within_limit_is_accepted() {
    let mut reply = Reply::json(INFO);
    reply.chunked = true;
    let server = MockServer::start(vec![reply]).await;
    let report = PreflightClient::new(config(&server.url, None))
        .unwrap()
        .run()
        .await;
    assert_eq!(report.nodes[0].requests[0].failure, None);
    assert_eq!(report.nodes[0].requests[0].response_bytes, INFO.len());
}

#[tokio::test]
async fn timeout_covers_waiting_for_headers() {
    let mut reply = Reply::json(INFO);
    reply.header_delay = Duration::from_secs(2);
    let server = MockServer::start(vec![reply]).await;
    let configured = config(&server.url, None)
        .with_limits(Duration::from_millis(50), 1024)
        .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert_eq!(report.nodes[0].requests[0].failure, Some(Failure::Timeout));
    assert_eq!(report.nodes[0].requests[0].status, None);
}

#[tokio::test]
async fn timeout_covers_slow_response_body() {
    let mut reply = Reply::json(INFO);
    reply.body_delay = Duration::from_secs(2);
    let server = MockServer::start(vec![reply]).await;
    let configured = config(&server.url, None)
        .with_limits(Duration::from_millis(50), 1024)
        .unwrap();
    let report = PreflightClient::new(configured).unwrap().run().await;
    assert_eq!(report.nodes[0].requests[0].failure, Some(Failure::Timeout));
    assert_eq!(report.nodes[0].requests[0].status, Some(200));
}

#[tokio::test]
async fn connection_failure_is_an_exportable_transport_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let report = PreflightClient::new(config(&endpoint, None))
        .unwrap()
        .run()
        .await;
    assert_eq!(
        report.nodes[0].requests[0].failure,
        Some(Failure::Transport)
    );
    assert!(report.nodes[0].info.is_none());
}

#[tokio::test]
async fn malformed_storage_and_registry_are_not_reported_as_success() {
    for (storage, authority) in [
        (json!({}), json!({})),
        (
            json!({"units":4,"limits":[{"name":SECRET,"limit":4,"used":0}]}),
            json!({"events":[{"fid":1}]}),
        ),
        (
            json!({"units":4,"limits":[{"name":"CASTS","limit":-1,"used":0}]}),
            serde_json::from_str(&registry(99)).unwrap(),
        ),
        (
            json!({"units":4,"limits":[{"name":"CASTS","limit":4,"used":0},{"name":"CASTS","limit":4,"used":0}]}),
            json!({"events":[{"fid":8531,"blockNumber":1,"txIndex":1,"logIndex":1,"idRegisterEventBody":{"eventType":"Transfer","to":SECRET}}]}),
        ),
    ] {
        let server = MockServer::start(vec![
            Reply::json(INFO),
            Reply::json(cast(json!(1), 8531)),
            Reply::json(storage.to_string()),
            Reply::json(authority.to_string()),
        ])
        .await;
        let report = PreflightClient::new(config(&server.url, Some(8531)))
            .unwrap()
            .run()
            .await;
        assert!(report.nodes[0].storage.is_none());
        assert!(report.nodes[0].authority.is_none());
        assert_eq!(
            report.nodes[0].requests[2].failure,
            Some(Failure::Malformed)
        );
        assert_eq!(
            report.nodes[0].requests[3].failure,
            Some(Failure::Malformed)
        );
        assert!(!serde_json::to_string(&report).unwrap().contains(SECRET));
    }
}

#[tokio::test]
async fn no_registry_events_do_not_imply_custody() {
    let server = MockServer::start(vec![
        Reply::json(INFO),
        Reply::json(cast(json!(1), 8531)),
        Reply::json(allocation()),
        Reply::json(r#"{"events":[]}"#),
    ])
    .await;
    let report = PreflightClient::new(config(&server.url, Some(8531)))
        .unwrap()
        .run()
        .await;
    let authority = report.nodes[0].authority.as_ref().unwrap();
    assert_eq!(authority.registry_events, 0);
    assert_eq!(authority.reported_custody, None);
    assert!(!authority.verified);
}
