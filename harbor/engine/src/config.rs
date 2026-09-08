use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub listen: SocketAddr,
    pub dns_listen: SocketAddr,
    pub dns_servers: Vec<SocketAddr>,
    #[serde(default)]
    pub dns_tls: Vec<DnsTlsServer>,
    #[serde(default)]
    pub egress_mode: EgressMode,
    pub nodes: Vec<Node>,
    pub groups: Vec<Group>,
    pub rules: Vec<Rule>,
    pub final_policy: String,
    #[serde(default)]
    pub routing_mode: RoutingMode,
    #[serde(default)]
    pub direct_exceptions: crate::exceptions::DirectExceptions,
    #[serde(default)]
    pub traffic_routes: Vec<crate::traffic_routes::TrafficRoute>,
    pub max_connections: usize,
    pub connect_timeout_ms: u64,
    pub idle_timeout_secs: u64,
    #[serde(default = "default_half_close")]
    pub half_close_timeout_secs: u64,
    pub probe_interval_secs: u64,
    #[serde(default)]
    pub tun: bool,
    #[serde(default)]
    pub privacy: crate::privacy::Privacy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            listen: "127.0.0.1:7897".parse().unwrap(),
            dns_listen: "127.0.0.1:5357".parse().unwrap(),
            dns_servers: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            dns_tls: vec![
                DnsTlsServer {
                    address: "223.5.5.5:443".parse().unwrap(),
                    server_name: "dns.alidns.com".into(),
                    ca_pem: String::new(),
                    https_path: Some("/dns-query".into()),
                },
                DnsTlsServer {
                    address: "1.1.1.1:443".parse().unwrap(),
                    server_name: "cloudflare-dns.com".into(),
                    ca_pem: String::new(),
                    https_path: Some("/dns-query".into()),
                },
            ],
            egress_mode: EgressMode::default(),
            nodes: vec![],
            groups: vec![],
            rules: vec![
                Rule {
                    kind: RuleKind::DomainSuffix,
                    value: "localhost".into(),
                    policy: "DIRECT".into(),
                    enabled: true,
                },
                Rule {
                    kind: RuleKind::IpCidr,
                    value: "127.0.0.0/8".into(),
                    policy: "DIRECT".into(),
                    enabled: true,
                },
                Rule {
                    kind: RuleKind::IpCidr,
                    value: "::1/128".into(),
                    policy: "DIRECT".into(),
                    enabled: true,
                },
            ],
            final_policy: "DIRECT".into(),
            routing_mode: RoutingMode::default(),
            direct_exceptions: Default::default(),
            traffic_routes: vec![],
            max_connections: 2048,
            connect_timeout_ms: 8000,
            idle_timeout_secs: 300,
            half_close_timeout_secs: 10,
            probe_interval_secs: 30,
            tun: false,
            privacy: Default::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    #[default]
    Physical,
    System,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    #[default]
    Rules,
    Global,
    Direct,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsTlsServer {
    pub address: SocketAddr,
    pub server_name: String,
    #[serde(default)]
    pub ca_pem: String,
    /// An HTTPS path selects DNS over HTTPS. None retains DNS over TLS framing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Http,
    Https,
    Socks5,
    Trojan,
    Shadowsocks,
    Vless,
    Vmess,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Node {
    pub name: String,
    pub kind: NodeKind,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub tls_server_name: String,
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    #[serde(default)]
    pub ws_host: String,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub ca_pem: String,
}
fn default_half_close() -> u64 {
    10
}
fn default_cipher() -> String {
    "chacha20-ietf-poly1305".into()
}
fn default_transport() -> String {
    "tcp".into()
}
fn default_ws_path() -> String {
    "/".into()
}
fn default_security() -> String {
    "auto".into()
}
impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("server", &self.server)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.username.zeroize();
        self.uuid.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Group {
    pub name: String,
    pub kind: GroupKind,
    pub members: Vec<String>,
    #[serde(default)]
    pub selected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<crate::pools::PoolSettings>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Select,
    Fallback,
    Latency,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub kind: RuleKind,
    pub value: String,
    pub policy: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn yes() -> bool {
    true
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    Port,
    Protocol,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        self.privacy.validate()?;
        self.direct_exceptions.validate()?;
        ensure!(
            self.version == 1,
            "Unsupported profile version: {}",
            self.version
        );
        ensure!(
            self.listen.ip().is_loopback() && self.dns_listen.ip().is_loopback(),
            "Listeners must use loopback addresses"
        );
        ensure!(
            self.listen.port() != 0 && self.dns_listen.port() != 0,
            "Listener ports must be nonzero"
        );
        ensure!(
            (1..=16384).contains(&self.max_connections),
            "maxConnections must be 1–16384"
        );
        ensure!(
            (500..=60000).contains(&self.connect_timeout_ms),
            "connectTimeoutMs must be 500–60000"
        );
        ensure!(
            (1..=300).contains(&self.half_close_timeout_secs),
            "halfCloseTimeoutSecs must be 1–300"
        );
        ensure!(
            (10..=86400).contains(&self.idle_timeout_secs),
            "idleTimeoutSecs must be 10–86400"
        );
        ensure!(
            (10..=3600).contains(&self.probe_interval_secs),
            "probeIntervalSecs must be 10–3600"
        );
        ensure!(
            !self.dns_servers.is_empty() && self.dns_servers.len() <= 4,
            "Configure 1–4 DNS servers"
        );
        ensure!(
            self.dns_tls.len() <= 4,
            "Configure at most four encrypted DNS servers"
        );
        for server in &self.dns_tls {
            ensure!(
                server.address.port() != 0
                    && !server.address.ip().is_unspecified()
                    && server.address != self.dns_listen,
                "Invalid encrypted DNS address"
            );
            rustls::pki_types::ServerName::try_from(server.server_name.clone())
                .map_err(|_| anyhow::anyhow!("Invalid DNS TLS authentication name"))?;
            ensure!(
                !server.server_name.is_empty() && server.ca_pem.len() <= 65536,
                "Invalid DNS TLS settings"
            );
            if let Some(path) = &server.https_path {
                ensure!(
                    path.starts_with('/')
                        && !path.starts_with("//")
                        && path.len() <= 2048
                        && !path.chars().any(|c| c.is_control() || c.is_whitespace())
                        && !path.contains('#'),
                    "Invalid DoH path"
                );
                let uri: hyper::Uri = path
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid DoH path"))?;
                ensure!(
                    uri.scheme().is_none() && uri.authority().is_none(),
                    "DoH path must be relative to the configured server"
                );
            }
        }
        ensure!(
            self.dns_servers
                .iter()
                .all(|s| s.port() != 0 && !s.ip().is_unspecified() && *s != self.dns_listen),
            "Invalid or recursive DNS server"
        );
        ensure!(
            self.nodes.len() <= 512 && self.groups.len() <= 128 && self.rules.len() <= 20000,
            "Profile exceeds resource limits"
        );
        let mut names: HashSet<&str> = ["DIRECT", "REJECT"].into();
        for node in &self.nodes {
            valid_name(&node.name)?;
            ensure!(
                names.insert(&node.name),
                "Duplicate/reserved name: {}",
                node.name
            );
            ensure!(
                !node.server.is_empty()
                    && node.server.len() <= 253
                    && !node.server.chars().any(|c| c.is_whitespace()
                        || c.is_control()
                        || matches!(c, '/' | '@' | '#')),
                "Invalid server for {}",
                node.name
            );
            ensure!(node.port > 0, "Missing port for {}", node.name);
            ensure!(
                node.username.len() <= 255 && node.password.len() <= 4096,
                "Credentials too long for {}",
                node.name
            );
            if node.kind == NodeKind::Socks5 {
                ensure!(
                    node.password.len() <= 255,
                    "SOCKS5 password exceeds 255 bytes"
                );
            }
            if matches!(node.kind, NodeKind::Trojan | NodeKind::Shadowsocks) {
                ensure!(
                    !node.password.is_empty(),
                    "Missing password for {}",
                    node.name
                );
            }
            if node.kind == NodeKind::Shadowsocks {
                if crate::ss2022::supported(&node.cipher) {
                    crate::ss2022::validate_key(&node.cipher, &node.password)?;
                }
                ensure!(
                    [
                        "chacha20-ietf-poly1305",
                        "aes-128-gcm",
                        "aes-256-gcm",
                        "2022-blake3-aes-128-gcm",
                        "2022-blake3-aes-256-gcm"
                    ]
                    .contains(&node.cipher.as_str()),
                    "Unsupported Shadowsocks cipher: {}",
                    node.cipher
                );
            }
            ensure!(
                ["tcp", "ws"].contains(&node.transport.as_str()),
                "Unsupported transport for {}",
                node.name
            );
            ensure!(
                node.tls_server_name.len() <= 253
                    && !node
                        .tls_server_name
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace()),
                "Invalid TLS server name"
            );
            ensure!(node.ca_pem.len() <= 65536, "Custom CA exceeds 64 KiB");
            ensure!(
                node.ws_path.starts_with('/')
                    && node.ws_path.len() <= 2048
                    && !node.ws_path.chars().any(char::is_control),
                "Invalid WebSocket path"
            );
            ensure!(
                node.ws_host.len() <= 253
                    && !node
                        .ws_host
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace()),
                "Invalid WebSocket host"
            );
            if node.transport == "ws" {
                ensure!(
                    matches!(
                        node.kind,
                        NodeKind::Vless | NodeKind::Vmess | NodeKind::Trojan
                    ),
                    "WebSocket is unsupported for this protocol"
                );
            }
            if matches!(node.kind, NodeKind::Vless | NodeKind::Vmess) {
                uuid::Uuid::parse_str(&node.uuid)
                    .map_err(|_| anyhow::anyhow!("Invalid UUID for {}", node.name))?;
            }
            if node.kind == NodeKind::Vless {
                ensure!(node.tls, "VLESS does not encrypt payloads; TLS is required");
            }
            if node.kind == NodeKind::Vmess {
                ensure!(
                    ["auto", "aes-128-gcm", "chacha20-poly1305"].contains(&node.security.as_str()),
                    "VMess requires authenticated encryption"
                );
            }
        }
        let nodes = names.clone();
        for group in &self.groups {
            valid_name(&group.name)?;
            ensure!(
                names.insert(&group.name),
                "Duplicate/reserved name: {}",
                group.name
            );
            ensure!(!group.members.is_empty(), "Empty group: {}", group.name);
            let mut unique = HashSet::new();
            for member in &group.members {
                ensure!(
                    nodes.contains(member.as_str()) && member != "REJECT",
                    "Unknown/nonterminal member {member} in {}",
                    group.name
                );
                ensure!(unique.insert(member), "Duplicate member in {}", group.name);
            }
            if let Some(selected) = &group.selected {
                ensure!(
                    group.members.contains(selected),
                    "Selected node is outside group {}",
                    group.name
                );
            }
        }
        ensure!(
            names.contains(self.final_policy.as_str()),
            "Unknown final policy: {}",
            self.final_policy
        );
        for (index, rule) in self.rules.iter().enumerate() {
            ensure!(
                names.contains(rule.policy.as_str()),
                "Rule {}: unknown policy {}",
                index + 1,
                rule.policy
            );
            ensure!(
                !rule.value.is_empty() && rule.value.len() <= 1024,
                "Rule {}: invalid value",
                index + 1
            );
            match rule.kind {
                RuleKind::IpCidr => {
                    rule.value
                        .parse::<IpNet>()
                        .map_err(|_| anyhow::anyhow!("Rule {}: invalid CIDR", index + 1))?;
                }
                RuleKind::Port => {
                    ensure!(
                        rule.value.parse::<u16>().is_ok_and(|p| p > 0),
                        "Rule {}: invalid port",
                        index + 1
                    );
                }
                RuleKind::Protocol => {
                    ensure!(
                        ["tcp", "udp"].contains(&rule.value.as_str()),
                        "Rule {}: protocol must be tcp or udp",
                        index + 1
                    );
                }
                _ => {
                    ensure!(
                        !rule.value.chars().any(char::is_whitespace),
                        "Rule {}: domain contains whitespace",
                        index + 1
                    );
                }
            }
        }
        crate::traffic_routes::validate(self, &names)?;
        crate::pools::validate(self)?;
        Ok(())
    }
}
fn valid_name(name: &str) -> Result<()> {
    if name.trim() != name
        || name.is_empty()
        || name.len() > 128
        || name.chars().any(char::is_control)
    {
        bail!("Invalid policy name");
    }
    Ok(())
}
