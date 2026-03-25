# Phase 13: OpenShell-Inspired Features — Implementation Plan

This document details how to implement six key features from NVIDIA OpenShell
in Guardian Shell, adapting them to our eBPF + Landlock architecture.

Each feature includes: motivation, architecture design, implementation steps
with file-by-file changes, new data structures, and testing strategy.

---

## Table of Contents

1. [L7 Network Inspection (Userspace HTTP Proxy)](#1-l7-network-inspection)
2. [Credential Isolation (Placeholder Injection)](#2-credential-isolation)
3. [Per-Binary Network Policy](#3-per-binary-network-policy)
4. [SSRF Prevention](#4-ssrf-prevention)
5. [Binary Integrity (SHA256 TOFU)](#5-binary-integrity-sha256-tofu)
6. [Cross-Platform Support via Container Mode](#6-cross-platform-container-mode)
7. [Implementation Order & Dependencies](#7-implementation-order)
8. [Risk Assessment](#8-risk-assessment)

---

## 1. L7 Network Inspection

### 1a. Motivation

Guardian Shell currently enforces network policy at L4 only — eBPF's
`sys_enter_connect` tracepoint sees the destination IP and port, and the LSM
`socket_connect` hook blocks with `-ECONNREFUSED`. This cannot distinguish:

- `GET /v1/models` (harmless) from `POST /v1/files` (data exfiltration)
- Read-only GitHub API calls from `git push`
- npm install from npm publish

L7 inspection lets us write policies like "allow GET but not POST to this host."

### 1b. Architecture

We add a **userspace transparent proxy** inside the cgroup agent's network
namespace. Unlike OpenShell (which uses a full Kubernetes network namespace +
veth pair), we use **iptables REDIRECT** inside the agent's cgroup network
namespace to transparently route outbound TCP to our proxy — no agent code
changes needed.

```
Agent process (inside cgroup)
    │
    │  connect("api.openai.com", 443)
    │
    ▼
iptables REDIRECT (in cgroup netns)
    │
    │  Redirects to 127.0.0.1:13128
    │
    ▼
┌─────────────────────────────────────────────┐
│  guardian-proxy (runs inside cgroup netns)   │
│                                             │
│  1. Recover original dest via SO_ORIGINAL_DST│
│  2. Read agent policy from shared config    │
│  3. L4 check: host:port allowed?            │
│  4. TLS intercept (ephemeral CA)            │
│  5. L7 check: method + path allowed?        │
│  6. Forward to real destination             │
└─────────────────────────────────────────────┘
```

**Why not a veth pair like OpenShell?** Guardian Shell operates at the process/
cgroup level, not containers. Creating network namespaces + veth pairs for every
agent would be a major architectural shift. iptables REDIRECT inside the existing
cgroup is simpler and keeps our lightweight deployment model.

**Alternative: eBPF sk_msg / sockmap.** For a zero-copy kernel-level approach,
we could use eBPF `sk_msg` programs to redirect socket traffic to the proxy
without iptables. This is more performant but significantly more complex. Start
with iptables, migrate to sk_msg later if performance matters.

### 1c. New Components

#### New crate: `guardian-proxy/`

```
guardian-proxy/
├── Cargo.toml
└── src/
    ├── main.rs          # Tokio TCP listener, connection dispatch
    ├── transparent.rs   # SO_ORIGINAL_DST recovery, iptables setup
    ├── tls.rs           # Ephemeral CA generation, TLS interception
    ├── l7.rs            # HTTP request parsing, method+path extraction
    ├── policy.rs        # L7 policy evaluation (from shared config)
    └── relay.rs         # Bidirectional TCP relay (plain + TLS)
```

#### New dependencies

```toml
# guardian-proxy/Cargo.toml
[dependencies]
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = "0.23"
rcgen = "0.13"                    # Ephemeral CA + leaf cert generation
webpki-roots = "1.0"             # Mozilla CA roots for upstream TLS
httparse = "1.9"                 # Zero-copy HTTP/1.1 request parsing
guardian-common = { path = "../guardian-common" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
log = "0.4"
env_logger = "0.11"
anyhow = "1"
libc = "0.2"
```

### 1d. Implementation Steps

#### Step 1: L7 Policy Configuration

**File: `guardian-common/src/lib.rs`**

Add L7 policy types to the shared crate:

```rust
/// L7 network policy rule — evaluated per HTTP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Rule {
    /// HTTP methods allowed (e.g., ["GET", "HEAD"] or ["*"] for any)
    pub methods: Vec<String>,
    /// URL path patterns (glob, e.g., ["/v1/chat/**"] or ["**"] for any)
    pub paths: Vec<String>,
}

/// L7 endpoint policy — host:port + optional HTTP-level rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Endpoint {
    pub host: String,           // Exact or glob pattern (e.g., "*.openai.com")
    pub port: u16,
    pub protocol: Option<String>, // "https", "http", or None (raw TCP, no L7)
    pub rules: Vec<L7Rule>,     // Empty = allow all methods/paths
    #[serde(default)]
    pub binaries: Vec<String>,  // Per-binary policy (Phase 13.3)
}

/// Full L7 network policy for an agent
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct L7NetworkPolicy {
    pub enabled: bool,
    pub endpoints: Vec<L7Endpoint>,
    /// Default action for hosts not matching any endpoint
    pub default: String,        // "deny" or "allow"
}
```

**File: `guardian/src/config.rs`**

Extend `AgentConfig` to include L7 policy:

```rust
// In AgentConfig struct:
pub l7_network_policy: Option<L7NetworkPolicy>,
```

**Config TOML example:**

```toml
[[agents]]
name = "coding-agent"
identity = "cgroup"

[agents.network_policy]
default = "deny"
allow_ports = [443, 80]

[agents.l7_network_policy]
enabled = true
default = "deny"

[[agents.l7_network_policy.endpoints]]
host = "api.anthropic.com"
port = 443
protocol = "https"

[[agents.l7_network_policy.endpoints.rules]]
methods = ["POST"]
paths = ["/v1/messages"]

[[agents.l7_network_policy.endpoints.rules]]
methods = ["GET"]
paths = ["/v1/models"]

[[agents.l7_network_policy.endpoints]]
host = "api.github.com"
port = 443
protocol = "https"

[[agents.l7_network_policy.endpoints.rules]]
methods = ["GET"]
paths = ["/repos/**", "/orgs/**"]
# No POST/PUT/DELETE — read-only GitHub access
```

#### Step 2: Ephemeral CA + TLS Interception

**File: `guardian-proxy/src/tls.rs`**

```rust
use rcgen::{CertificateParams, KeyPair, DnType, IsCa, BasicConstraints};
use rustls::{ServerConfig, ClientConfig};
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-sandbox ephemeral Certificate Authority
pub struct SandboxCa {
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
    ca_pem: String,
    leaf_cache: Mutex<HashMap<String, Arc<CertifiedLeaf>>>,
}

pub struct CertifiedLeaf {
    pub server_config: Arc<ServerConfig>,
}

impl SandboxCa {
    /// Generate a new ephemeral CA (call once per agent sandbox)
    pub fn generate() -> anyhow::Result<Self> {
        let ca_key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "Guardian Shell Sandbox CA");
        params.distinguished_name.push(DnType::OrganizationalUnitName, "Guardian Shell");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        // Valid for 24 hours — sandbox lifetime
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(24);
        let ca_cert = params.self_signed(&ca_key)?;
        let ca_pem = ca_cert.pem();
        Ok(Self { ca_key, ca_cert, ca_pem, leaf_cache: Mutex::new(HashMap::new()) })
    }

    /// Get or create a leaf certificate for a hostname
    pub fn leaf_for_host(&self, hostname: &str) -> anyhow::Result<Arc<CertifiedLeaf>> {
        let mut cache = self.leaf_cache.lock().unwrap();
        if let Some(leaf) = cache.get(hostname) {
            return Ok(Arc::clone(leaf));
        }
        // Evict if cache too large (prevent memory leak)
        if cache.len() >= 256 {
            cache.clear();
        }
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(hostname.try_into()?),
        ];
        let leaf_cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;
        // Build rustls ServerConfig with this leaf
        let cert_chain = vec![
            rustls::pki_types::CertificateDer::from(leaf_cert.der().to_vec()),
            rustls::pki_types::CertificateDer::from(self.ca_cert.der().to_vec()),
        ];
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(
            leaf_key.serialize_der()
        )?;
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)?
        );
        let leaf = Arc::new(CertifiedLeaf { server_config });
        cache.insert(hostname.to_string(), Arc::clone(&leaf));
        Ok(leaf)
    }

    /// CA certificate PEM — inject into agent's trust store
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }
}
```

#### Step 3: Transparent Proxy Core

**File: `guardian-proxy/src/transparent.rs`**

```rust
use std::net::SocketAddr;

/// Recover original destination from SO_ORIGINAL_DST (set by iptables REDIRECT)
pub fn get_original_dst(stream: &tokio::net::TcpStream) -> anyhow::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    // getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, ...)
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as _;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            80, // SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        anyhow::bail!("getsockopt SO_ORIGINAL_DST failed: {}", std::io::Error::last_os_error());
    }
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(ip.into(), port))
}

/// Set up iptables REDIRECT rules inside the agent's cgroup network namespace
/// Called by guardian-launch before exec'ing the agent
pub fn setup_iptables_redirect(proxy_port: u16, agent_uid: u32) -> anyhow::Result<()> {
    // Redirect all outbound TCP from the agent's UID to the proxy
    // Using --uid-owner ensures only the agent's traffic is redirected,
    // not the proxy's own outbound connections
    let rules = [
        // Skip proxy's own traffic (proxy runs as root or a dedicated user)
        format!(
            "iptables -t nat -A OUTPUT -m owner --uid-owner 0 -j RETURN"
        ),
        // Redirect agent's TCP to proxy
        format!(
            "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner {} -j REDIRECT --to-port {}",
            agent_uid, proxy_port
        ),
    ];
    for rule in &rules {
        let status = std::process::Command::new("sh")
            .args(["-c", rule])
            .status()?;
        if !status.success() {
            anyhow::bail!("iptables rule failed: {}", rule);
        }
    }
    Ok(())
}
```

#### Step 4: HTTP Request Parsing + L7 Evaluation

**File: `guardian-proxy/src/l7.rs`**

```rust
use httparse;

pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Parse an HTTP/1.1 request from a byte buffer
pub fn parse_http_request(buf: &[u8]) -> anyhow::Result<Option<ParsedRequest>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf)? {
        httparse::Status::Complete(_len) => {
            let method = req.method.unwrap_or("").to_uppercase();
            let path = req.path.unwrap_or("/").to_string();
            let host = req.headers.iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .map(|s| s.to_string());
            let headers = req.headers.iter()
                .filter(|h| h.name != httparse::EMPTY_HEADER.name)
                .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string()))
                .collect();
            Ok(Some(ParsedRequest { method, path, host, headers }))
        }
        httparse::Status::Partial => Ok(None), // Need more data
    }
}

/// Evaluate L7 policy against a parsed HTTP request
pub fn evaluate_l7_policy(
    req: &ParsedRequest,
    dest_host: &str,
    dest_port: u16,
    policy: &L7NetworkPolicy,
) -> L7Decision {
    // Find matching endpoint
    for endpoint in &policy.endpoints {
        if !host_matches(&endpoint.host, dest_host) {
            continue;
        }
        if endpoint.port != dest_port {
            continue;
        }
        // Endpoint matches — check L7 rules
        if endpoint.rules.is_empty() {
            // No rules = allow all methods/paths for this endpoint
            return L7Decision::Allow;
        }
        for rule in &endpoint.rules {
            if method_matches(&rule.methods, &req.method)
                && path_matches(&rule.paths, &req.path)
            {
                return L7Decision::Allow;
            }
        }
        // Endpoint matched but no rule matched — deny
        return L7Decision::Deny {
            reason: format!(
                "{} {} not allowed for {}:{}",
                req.method, req.path, dest_host, dest_port
            ),
        };
    }
    // No endpoint matched — use default
    match policy.default.as_str() {
        "allow" => L7Decision::Allow,
        _ => L7Decision::Deny {
            reason: format!("{}:{} not in any L7 endpoint policy", dest_host, dest_port),
        },
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    // Glob: *.example.com matches sub.example.com
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        return host.ends_with(suffix) && !host[..host.len() - suffix.len()].contains('.');
    }
    false
}

fn method_matches(allowed: &[String], method: &str) -> bool {
    allowed.iter().any(|m| m == "*" || m.eq_ignore_ascii_case(method))
}

fn path_matches(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| {
        if p == "**" {
            return true;
        }
        // Reuse Guardian Shell's existing path_matches() logic
        crate::policy::glob_match(p, path)
    })
}

pub enum L7Decision {
    Allow,
    Deny { reason: String },
}
```

#### Step 5: Proxy Main Loop

**File: `guardian-proxy/src/main.rs`**

```rust
/// guardian-proxy runs inside the agent's cgroup (spawned by guardian-launch)
/// It listens on 127.0.0.1:13128 and intercepts redirected TCP connections.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = load_proxy_config()?; // From env var or file
    let ca = SandboxCa::generate()?;

    // Write CA cert for agent's trust store
    write_ca_cert(&ca, &config.ca_cert_path)?;

    let listener = TcpListener::bind("127.0.0.1:13128").await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let ca = ca.clone();
        let policy = config.l7_policy.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &ca, &policy).await {
                log::warn!("Proxy connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    client: TcpStream,
    ca: &SandboxCa,
    policy: &L7NetworkPolicy,
) -> anyhow::Result<()> {
    // 1. Recover original destination
    let original_dst = get_original_dst(&client)?;
    let dest_host = reverse_dns_or_ip(&original_dst);
    let dest_port = original_dst.port();

    // 2. L4 check: is this host:port allowed at all?
    // (eBPF already did port-level check, but we recheck for L7 endpoints)

    // 3. SSRF check (Phase 13.4)
    if is_ssrf_target(&original_dst.ip()) {
        log::warn!("SSRF blocked: {} → {}", dest_host, original_dst);
        return Ok(());
    }

    // 4. Connect upstream
    let upstream = TcpStream::connect(original_dst).await?;

    // 5. Check if L7 inspection is needed for this endpoint
    let endpoint = find_matching_endpoint(policy, &dest_host, dest_port);
    let needs_l7 = endpoint.map_or(false, |e| e.protocol.is_some());

    if !needs_l7 {
        // Raw TCP relay — no L7 inspection
        relay_bidirectional(client, upstream).await?;
        return Ok(());
    }

    // 6. Auto-detect TLS
    let mut peek_buf = [0u8; 8];
    let n = client.peek(&mut peek_buf).await?;
    let is_tls = n >= 3 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03;

    if is_tls {
        // TLS interception: terminate client TLS, inspect HTTP, re-encrypt upstream
        let leaf = ca.leaf_for_host(&dest_host)?;
        let client_tls = tls_accept_client(client, &leaf).await?;
        let upstream_tls = tls_connect_upstream(upstream, &dest_host).await?;
        relay_with_l7_inspection(client_tls, upstream_tls, &dest_host, dest_port, policy).await?;
    } else {
        // Plaintext HTTP — inspect directly
        relay_with_l7_inspection(client, upstream, &dest_host, dest_port, policy).await?;
    }
    Ok(())
}
```

#### Step 6: Integration with guardian-launch

**File: `guardian-launch/src/main.rs`**

After sandbox setup but before exec'ing the agent, spawn the proxy:

```rust
// After Landlock + seccomp setup, before exec:

if sandbox_config.l7_network_policy.as_ref().map_or(false, |p| p.enabled) {
    // 1. Write L7 policy to temp file for proxy to read
    let policy_path = format!("/tmp/guardian-proxy-{}.json", std::process::id());
    let policy_json = serde_json::to_string(&sandbox_config.l7_network_policy)?;
    std::fs::write(&policy_path, &policy_json)?;

    // 2. Spawn guardian-proxy as a background process (inside the cgroup)
    let proxy = std::process::Command::new("guardian-proxy")
        .env("GUARDIAN_PROXY_POLICY", &policy_path)
        .env("GUARDIAN_PROXY_CA_PATH", "/tmp/guardian-ca.pem")
        .spawn()?;

    // 3. Wait for proxy to be ready (listen on 13128)
    wait_for_port(13128, Duration::from_secs(5))?;

    // 4. Set up iptables REDIRECT (requires CAP_NET_ADMIN before dropping)
    setup_iptables_redirect(13128, target_uid)?;

    // 5. Inject CA cert into agent environment
    std::env::set_var("SSL_CERT_FILE", "/tmp/guardian-ca-bundle.pem");
    std::env::set_var("NODE_EXTRA_CA_CERTS", "/tmp/guardian-ca.pem");
    std::env::set_var("REQUESTS_CA_BUNDLE", "/tmp/guardian-ca-bundle.pem");
}

// Then exec the agent command as before
```

#### Step 7: L7 Events in Dashboard

**File: `guardian-common/src/lib.rs`**

```rust
/// L7 network event — emitted by guardian-proxy, consumed by daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7NetworkEvent {
    pub agent_name: String,
    pub timestamp: String,
    pub dest_host: String,
    pub dest_port: u16,
    pub method: String,
    pub path: String,
    pub action: String,       // "allow" or "deny"
    pub reason: Option<String>,
    pub binary_path: Option<String>,  // Phase 13.3
    pub binary_sha256: Option<String>, // Phase 13.5
}
```

The proxy sends L7 events to the daemon via a Unix socket (separate from the
main IPC socket) or by writing to a shared log file that the daemon tails. The
simplest approach is a UDP datagram to `127.0.0.1:13129` — fire-and-forget,
no connection overhead, daemon listens on this port for L7 events.

### 1e. Testing Strategy

1. **Unit tests**: `l7.rs` — parse HTTP requests, evaluate L7 policy
2. **Integration test**: Launch a cgroup agent with L7 policy, make HTTP requests
   from inside, verify allowed/blocked
3. **TLS test**: Verify ephemeral CA generation, leaf cert caching, client trust
4. **Bypass test**: Attempt direct TCP without proxy (iptables should redirect)
5. **Performance test**: Measure latency overhead of proxy for typical API calls

---

## 2. Credential Isolation

### 2a. Motivation

Guardian Shell agents currently have full access to environment variables and
config files. An agent launched with `ANTHROPIC_API_KEY=sk-ant-...` can:

```bash
cat /proc/self/environ | tr '\0' '\n' | grep API_KEY
# Exfiltrate the key to an external service
```

OpenShell solves this with placeholder injection — the agent never sees real
credentials.

### 2b. Architecture

```
guardian-launch (before exec)
    │
    │  Real env: ANTHROPIC_API_KEY=sk-ant-real-key
    │
    │  1. Scan env for credential patterns
    │  2. Replace values with placeholders
    │  3. Store mapping: placeholder → real value
    │  4. Write mapping to proxy config
    │  5. Set agent env to placeholders
    │
    ▼
Agent process (inside sandbox)
    │
    │  Sees: ANTHROPIC_API_KEY=guardian:cred:ANTHROPIC_API_KEY
    │
    │  Makes HTTP request:
    │  Authorization: Bearer guardian:cred:ANTHROPIC_API_KEY
    │
    ▼
guardian-proxy (intercepts)
    │
    │  Scans headers for "guardian:cred:" prefix
    │  Replaces with real value from stored mapping
    │  Forwards request with real credentials
    │
    ▼
api.anthropic.com receives real key
```

**Dependency**: Requires L7 proxy (Phase 13.1) to be implemented first, since
credential substitution happens at the HTTP header level.

### 2c. Implementation Steps

#### Step 1: Credential Configuration

**File: `guardian/src/config.rs`**

```rust
/// Credential isolation configuration for an agent
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialConfig {
    /// Enable credential isolation (requires L7 proxy)
    pub enabled: bool,
    /// Environment variable names to isolate
    /// If empty, auto-detect common patterns (API_KEY, SECRET, TOKEN, PASSWORD)
    pub env_vars: Vec<String>,
    /// Credential files to remove from sandbox filesystem
    /// These paths are added to Landlock deny list
    pub deny_files: Vec<String>,
}
```

**Config TOML example:**

```toml
[[agents]]
name = "coding-agent"
identity = "cgroup"

[agents.credentials]
enabled = true
# Explicit list — or leave empty for auto-detection
env_vars = ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY"]
# Block access to credential files
deny_files = [
    "~/.config/gh/hosts.yml",
    "~/.anthropic/credentials",
    "~/.aws/credentials",
    "~/.ssh/id_*",
]
```

#### Step 2: Credential Resolver

**New file: `guardian-common/src/credentials.rs`**

```rust
use std::collections::HashMap;

const CREDENTIAL_PREFIX: &str = "guardian:cred:";

/// Patterns that indicate an env var contains a credential
const AUTO_DETECT_PATTERNS: &[&str] = &[
    "API_KEY", "API_SECRET", "SECRET_KEY", "ACCESS_TOKEN",
    "AUTH_TOKEN", "PRIVATE_KEY", "PASSWORD", "PASSWD",
    "_TOKEN", "_SECRET", "_CREDENTIAL",
];

/// Manages placeholder ↔ real credential mappings
#[derive(Debug, Clone)]
pub struct CredentialResolver {
    /// placeholder string → real credential value
    mapping: HashMap<String, String>,
}

impl CredentialResolver {
    /// Build resolver from environment, replacing real values with placeholders.
    /// Returns (resolver, modified_env) where modified_env has placeholders.
    pub fn from_env(
        env_vars: &[String],
        auto_detect: bool,
    ) -> (Self, HashMap<String, String>) {
        let mut mapping = HashMap::new();
        let mut child_env = HashMap::new();

        for (key, value) in std::env::vars() {
            let should_isolate = if env_vars.is_empty() && auto_detect {
                let upper = key.to_uppercase();
                AUTO_DETECT_PATTERNS.iter().any(|p| upper.contains(p))
                    && !value.is_empty()
            } else {
                env_vars.iter().any(|v| v == &key)
            };

            if should_isolate && !value.is_empty() {
                let placeholder = format!("{}{}", CREDENTIAL_PREFIX, key);
                mapping.insert(placeholder.clone(), value);
                child_env.insert(key, placeholder);
            } else {
                child_env.insert(key, value);
            }
        }

        (Self { mapping }, child_env)
    }

    /// Replace placeholders in an HTTP header value with real credentials.
    /// Returns None if no substitution was needed.
    pub fn substitute(&self, header_value: &str) -> Option<String> {
        if !header_value.contains(CREDENTIAL_PREFIX) {
            return None;
        }
        let mut result = header_value.to_string();
        for (placeholder, real) in &self.mapping {
            if result.contains(placeholder.as_str()) {
                result = result.replace(placeholder.as_str(), real);
            }
        }
        Some(result)
    }

    /// Serialize mapping for proxy config
    pub fn to_proxy_config(&self) -> HashMap<String, String> {
        self.mapping.clone()
    }
}
```

#### Step 3: Integration with guardian-launch

**File: `guardian-launch/src/main.rs`**

```rust
// After reading SandboxConfig from daemon, before exec:

let child_env = if sandbox_config.credentials.as_ref().map_or(false, |c| c.enabled) {
    let cred_config = sandbox_config.credentials.as_ref().unwrap();
    let (resolver, modified_env) = CredentialResolver::from_env(
        &cred_config.env_vars,
        cred_config.env_vars.is_empty(), // auto-detect if no explicit list
    );

    // Write credential mapping for proxy
    let cred_path = format!("/tmp/guardian-creds-{}.json", std::process::id());
    let cred_json = serde_json::to_string(&resolver.to_proxy_config())?;
    std::fs::write(&cred_path, &cred_json)?;
    // Set restrictive permissions — only root (proxy) can read
    std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o600))?;

    log::info!(
        "Credential isolation: {} env vars replaced with placeholders",
        resolver.to_proxy_config().len()
    );

    // Add credential file paths to Landlock deny list
    for deny_path in &cred_config.deny_files {
        let expanded = shellexpand::tilde(deny_path).to_string();
        // These get added to Landlock rules (no read access)
        landlock_deny_paths.push(expanded);
    }

    modified_env
} else {
    std::env::vars().collect()
};

// Use child_env when exec'ing the agent
```

#### Step 4: Proxy Credential Substitution

**File: `guardian-proxy/src/main.rs`**

```rust
// In relay_with_l7_inspection(), after parsing each HTTP request:

fn rewrite_credentials(req: &mut ParsedRequest, resolver: &CredentialResolver) {
    for (name, value) in req.headers.iter_mut() {
        if let Some(substituted) = resolver.substitute(value) {
            log::debug!("Credential substituted in header: {}", name);
            *value = substituted;
        }
    }
}
```

### 2d. Security Considerations

- Credential mapping file must be root-owned, mode 0600, deleted after proxy reads it
- Proxy process runs as root (before privilege drop) to read credentials, then drops
- If agent gains root (shouldn't, due to seccomp + NO_NEW_PRIVS), it could read the proxy's memory — this is the same trust boundary as OpenShell
- Auto-detection patterns may have false positives — prefer explicit `env_vars` list
- Credential substitution only works for HTTP headers — credentials in request bodies (e.g., JSON `{"api_key": "..."}`) would require body parsing, which is out of scope for Phase 13

### 2e. Testing Strategy

1. **Unit tests**: `CredentialResolver` — placeholder generation, substitution, auto-detection
2. **Integration test**: Launch agent with `ANTHROPIC_API_KEY`, verify agent sees placeholder, verify proxy substitutes correctly
3. **Negative test**: Agent attempts `cat /proc/self/environ` — sees only placeholders
4. **File deny test**: Agent attempts to read `~/.aws/credentials` — blocked by Landlock

---

## 3. Per-Binary Network Policy

### 3a. Motivation

Guardian Shell's network enforcement is per-agent (cgroup). All processes in a
cgroup share the same network permissions. This means user-generated code (scripts
the agent writes and runs) gets the same network access as the agent itself.

OpenShell solves this with `/proc`-based binary identification at the proxy level.

### 3b. Architecture

```
Agent process tree (all in same cgroup):
  bash
  ├── node /usr/local/bin/claude     (agent)
  │   ├── git push origin main       (git — needs github.com)
  │   ├── npm install                 (npm — needs registry.npmjs.org)
  │   └── python exploit.py          (untrusted — needs nothing)
  │       └── connect(evil.com:443)
  │
  ▼
guardian-proxy receives connection from python
  │
  │ 1. getsockopt(SO_ORIGINAL_DST) → evil.com:443
  │ 2. Find socket owner via /proc/net/tcp → PID 5678
  │ 3. readlink(/proc/5678/exe) → /usr/bin/python3
  │ 4. Walk ancestors: python3 → node → claude → bash
  │ 5. Policy check: python3 not in any binary allowlist
  │ 6. DENY
  │
  ▼
python gets connection refused
```

### 3c. Implementation Steps

#### Step 1: Process Identity Resolution

**New file: `guardian-proxy/src/procfs.rs`**

```rust
use std::path::PathBuf;
use std::net::SocketAddr;

/// Identity of the process that owns a network connection
#[derive(Debug, Clone)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub binary_path: PathBuf,
    pub binary_sha256: String,        // Phase 13.5
    pub ancestors: Vec<PathBuf>,      // Parent chain binary paths
}

/// Find which PID owns a TCP connection by matching source port
/// in /proc/net/tcp
pub fn resolve_socket_owner(
    entrypoint_pid: u32,
    client_port: u16,
) -> anyhow::Result<u32> {
    // Read /proc/{entrypoint_pid}/net/tcp (sees all connections in namespace)
    let tcp_path = format!("/proc/{}/net/tcp", entrypoint_pid);
    let content = std::fs::read_to_string(&tcp_path)?;

    // Parse /proc/net/tcp format:
    //   sl  local_address rem_address   st tx_queue ... inode
    //    0: 0100007F:3348 0100007F:0050 01 ...      12345
    let target_port_hex = format!("{:04X}", client_port);
    let mut target_inode: Option<u64> = None;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // local_address is field[1], format "ADDR:PORT"
        if let Some(port_hex) = fields[1].split(':').nth(1) {
            if port_hex == target_port_hex {
                // inode is field[9]
                if let Ok(ino) = fields[9].parse::<u64>() {
                    target_inode = Some(ino);
                    break;
                }
            }
        }
    }

    let inode = target_inode.ok_or_else(|| {
        anyhow::anyhow!("Socket with port {} not found in /proc/net/tcp", client_port)
    })?;

    // Walk /proc to find PID owning this socket inode
    find_pid_by_socket_inode(entrypoint_pid, inode)
}

/// Search /proc/{pid}/fd/* for socket:[{inode}]
fn find_pid_by_socket_inode(entrypoint_pid: u32, inode: u64) -> anyhow::Result<u32> {
    let target = format!("socket:[{}]", inode);

    // First: search descendants of entrypoint via /proc/{pid}/task/{tid}/children
    if let Some(pid) = search_descendants(entrypoint_pid, &target) {
        return Ok(pid);
    }

    // Fallback: scan all /proc entries
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(link) = std::fs::read_link(fd.path()) {
                        if link.to_string_lossy() == target {
                            return Ok(pid);
                        }
                    }
                }
            }
        }
    }

    anyhow::bail!("No process found owning socket inode {}", inode)
}

/// Walk /proc/{pid}/task/{tid}/children recursively
fn search_descendants(pid: u32, target_link: &str) -> Option<u32> {
    // Check this PID's fds
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(fds) = std::fs::read_dir(&fd_dir) {
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if link.to_string_lossy() == *target_link {
                    return Some(pid);
                }
            }
        }
    }

    // Recurse into children
    let children_path = format!("/proc/{}/task/{}/children", pid, pid);
    if let Ok(children) = std::fs::read_to_string(&children_path) {
        for child_str in children.split_whitespace() {
            if let Ok(child_pid) = child_str.parse::<u32>() {
                if let Some(found) = search_descendants(child_pid, target_link) {
                    return Some(found);
                }
            }
        }
    }

    None
}

/// Get the binary path and ancestor chain for a PID
pub fn get_process_identity(pid: u32, entrypoint_pid: u32) -> anyhow::Result<ProcessIdentity> {
    // Binary path from /proc/{pid}/exe (kernel-maintained, unspoofable)
    let binary_path = std::fs::read_link(format!("/proc/{}/exe", pid))?;

    // Walk parent chain via PPid in /proc/{pid}/status
    let mut ancestors = Vec::new();
    let mut current_pid = pid;
    for _ in 0..64 {
        // Depth limit
        let status = std::fs::read_to_string(format!("/proc/{}/status", current_pid))?;
        let ppid = status.lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);

        if ppid == 0 || ppid == 1 || ppid == current_pid || current_pid == entrypoint_pid {
            break;
        }

        if let Ok(parent_exe) = std::fs::read_link(format!("/proc/{}/exe", ppid)) {
            ancestors.push(parent_exe);
        }
        current_pid = ppid;
    }

    // SHA256 hash (Phase 13.5 — placeholder for now)
    let binary_sha256 = String::new();

    Ok(ProcessIdentity { pid, binary_path, binary_sha256, ancestors })
}
```

#### Step 2: Binary Policy in L7 Endpoint Config

The `L7Endpoint.binaries` field from Phase 13.1 is already defined.
Matching logic:

```rust
/// Check if a process identity matches the binary policy
pub fn binary_matches(
    allowed_binaries: &[String],
    identity: &ProcessIdentity,
) -> bool {
    if allowed_binaries.is_empty() {
        return true; // No binary restriction
    }

    for allowed in allowed_binaries {
        // Check direct binary path
        if path_or_glob_matches(allowed, &identity.binary_path) {
            return true;
        }
        // Check ancestor chain (e.g., policy says "/usr/local/bin/claude"
        // and the actual binary is "node", but claude is an ancestor)
        for ancestor in &identity.ancestors {
            if path_or_glob_matches(allowed, ancestor) {
                return true;
            }
        }
    }

    false
}

fn path_or_glob_matches(pattern: &str, path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    if pattern == path_str.as_ref() {
        return true;
    }
    if pattern.contains('*') {
        return glob_match(pattern, &path_str);
    }
    false
}
```

#### Step 3: Integrate into Proxy Connection Handler

**File: `guardian-proxy/src/main.rs`**

```rust
async fn handle_connection(/* ... */) -> anyhow::Result<()> {
    let original_dst = get_original_dst(&client)?;

    // Identify calling binary
    let client_port = client.peer_addr()?.port();
    let owner_pid = resolve_socket_owner(entrypoint_pid, client_port)?;
    let identity = get_process_identity(owner_pid, entrypoint_pid)?;

    log::info!(
        "Connection from {} (pid {}) → {}:{}",
        identity.binary_path.display(), identity.pid,
        dest_host, dest_port
    );

    // L4 + binary check
    let endpoint = find_matching_endpoint(policy, &dest_host, dest_port);
    if let Some(ep) = &endpoint {
        if !binary_matches(&ep.binaries, &identity) {
            log::warn!(
                "DENY: binary {} not allowed for {}:{}",
                identity.binary_path.display(), dest_host, dest_port
            );
            // Send L7 event to daemon
            send_l7_event(L7NetworkEvent {
                action: "deny".to_string(),
                reason: Some(format!(
                    "binary {} not in allowlist",
                    identity.binary_path.display()
                )),
                binary_path: Some(identity.binary_path.to_string_lossy().to_string()),
                ..
            });
            // Close connection (agent sees connection reset)
            return Ok(());
        }
    }

    // Continue with L7 inspection...
}
```

### 3d. Testing Strategy

1. **Unit tests**: Process identity resolution from mock /proc data
2. **Integration test**: Launch cgroup agent, spawn `curl` and `python` inside,
   verify curl allowed to reach endpoint but python blocked
3. **Ancestor test**: Verify that `node /usr/local/bin/claude` matches policy
   for `/usr/local/bin/claude` even though exe is `/usr/bin/node`

---

## 4. SSRF Prevention

### 4a. Motivation

Guardian Shell's L7 proxy (Phase 13.1) will forward connections to upstream
hosts. Without SSRF prevention, an agent could trick the proxy into connecting to
internal services:

- AWS/GCP metadata service (`169.254.169.254`)
- Local services (`127.0.0.1:*`)
- Private network hosts (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Kubernetes API (if running in k8s)

This is especially dangerous because the proxy runs outside the agent's
Landlock/seccomp sandbox and has unrestricted network access.

### 4b. Architecture

```
Agent: connect(evil.com:443)
    │
    ▼
Proxy:
    │
    ├── 1. OPA/L7 policy check → evil.com:443 allowed? → YES
    │
    ├── 2. DNS resolve evil.com → [169.254.169.254]
    │
    ├── 3. SSRF check:
    │       169.254.169.254 → Tier 1 (link-local) → ALWAYS BLOCKED
    │       → DENY
    │
    └── 4. Connection never established
```

### 4c. Implementation Steps

#### Step 1: IP Classification

**New file: `guardian-proxy/src/ssrf.rs`**

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ports that are always blocked regardless of IP or policy
const CONTROL_PLANE_PORTS: &[u16] = &[
    2379,  // etcd client
    2380,  // etcd peer
    6443,  // Kubernetes API
    10250, // kubelet
    10255, // kubelet read-only
];

/// Result of SSRF IP check
#[derive(Debug)]
pub enum SsrfCheck {
    /// IP is safe for connection
    Safe,
    /// IP is always blocked (loopback, link-local, unspecified)
    AlwaysBlocked { reason: &'static str },
    /// IP is in private range (RFC 1918, ULA) — blocked by default
    PrivateRange { reason: &'static str },
    /// Port is always blocked (control plane)
    BlockedPort { port: u16 },
}

/// Check if an IP address is an SSRF target
pub fn check_ip(ip: &IpAddr, port: u16) -> SsrfCheck {
    // Check control plane ports first
    if CONTROL_PLANE_PORTS.contains(&port) {
        return SsrfCheck::BlockedPort { port };
    }

    match ip {
        IpAddr::V4(v4) => check_ipv4(v4),
        IpAddr::V6(v6) => check_ipv6(v6),
    }
}

fn check_ipv4(ip: &Ipv4Addr) -> SsrfCheck {
    // Tier 1: Always blocked (cannot be overridden)
    if ip.is_loopback() {
        return SsrfCheck::AlwaysBlocked { reason: "loopback (127.0.0.0/8)" };
    }
    if ip.is_link_local() {
        // 169.254.0.0/16 — AWS/GCP metadata service
        return SsrfCheck::AlwaysBlocked { reason: "link-local (169.254.0.0/16)" };
    }
    if ip.is_unspecified() {
        return SsrfCheck::AlwaysBlocked { reason: "unspecified (0.0.0.0)" };
    }
    if ip.is_broadcast() {
        return SsrfCheck::AlwaysBlocked { reason: "broadcast (255.255.255.255)" };
    }

    // Tier 2: Private ranges (blocked by default, overridable with allowed_ips)
    if ip.is_private() {
        return SsrfCheck::PrivateRange { reason: "RFC 1918 private range" };
    }

    // 100.64.0.0/10 — Carrier-grade NAT (shared address space)
    let octets = ip.octets();
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return SsrfCheck::PrivateRange { reason: "CGNAT (100.64.0.0/10)" };
    }

    // 192.0.0.0/24 — IETF protocol assignments
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return SsrfCheck::PrivateRange { reason: "IETF protocol (192.0.0.0/24)" };
    }

    SsrfCheck::Safe
}

fn check_ipv6(ip: &Ipv6Addr) -> SsrfCheck {
    // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x) — unwrap and check as IPv4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_ipv4(&v4);
    }

    if ip.is_loopback() {
        return SsrfCheck::AlwaysBlocked { reason: "IPv6 loopback (::1)" };
    }
    if ip.is_unspecified() {
        return SsrfCheck::AlwaysBlocked { reason: "IPv6 unspecified (::)" };
    }

    // fe80::/10 — link-local
    let segments = ip.segments();
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return SsrfCheck::AlwaysBlocked { reason: "IPv6 link-local (fe80::/10)" };
    }

    // fc00::/7 — unique local address (ULA, private equivalent)
    if (segments[0] & 0xFE00) == 0xFC00 {
        return SsrfCheck::PrivateRange { reason: "IPv6 ULA (fc00::/7)" };
    }

    SsrfCheck::Safe
}

/// Resolve hostname and check ALL returned IPs for SSRF
pub async fn resolve_and_check(
    host: &str,
    port: u16,
    allowed_ips: &[IpNetwork],
) -> Result<Vec<SocketAddr>, SsrfError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::DnsResolutionFailed(host.to_string()));
    }

    for addr in &addrs {
        let check = check_ip(&addr.ip(), port);
        match check {
            SsrfCheck::Safe => {}
            SsrfCheck::AlwaysBlocked { reason } => {
                // Cannot be overridden
                return Err(SsrfError::Blocked {
                    ip: addr.ip(),
                    reason: reason.to_string(),
                });
            }
            SsrfCheck::PrivateRange { reason } => {
                // Check if overridden by allowed_ips
                if !allowed_ips.iter().any(|net| net.contains(addr.ip())) {
                    return Err(SsrfError::Blocked {
                        ip: addr.ip(),
                        reason: reason.to_string(),
                    });
                }
            }
            SsrfCheck::BlockedPort { port } => {
                return Err(SsrfError::BlockedPort { port });
            }
        }
    }

    Ok(addrs)
}

#[derive(Debug)]
pub enum SsrfError {
    DnsResolutionFailed(String),
    Blocked { ip: IpAddr, reason: String },
    BlockedPort { port: u16 },
    Io(std::io::Error),
}
```

#### Step 2: Integrate into Proxy

**File: `guardian-proxy/src/main.rs`**

```rust
async fn handle_connection(/* ... */) -> anyhow::Result<()> {
    let original_dst = get_original_dst(&client)?;
    let dest_host = reverse_dns_or_ip(&original_dst);
    let dest_port = original_dst.port();

    // SSRF check: resolve DNS and validate all IPs
    let endpoint = find_matching_endpoint(policy, &dest_host, dest_port);
    let allowed_ips = endpoint
        .and_then(|e| e.allowed_ips.as_ref())
        .unwrap_or(&Vec::new());

    match resolve_and_check(&dest_host, dest_port, allowed_ips).await {
        Ok(addrs) => {
            // Use first safe address for upstream connection
            let upstream = TcpStream::connect(addrs[0]).await?;
            // Continue with L7 inspection...
        }
        Err(SsrfError::Blocked { ip, reason }) => {
            log::warn!("SSRF blocked: {} (resolved to {}) — {}", dest_host, ip, reason);
            send_l7_event(L7NetworkEvent {
                action: "deny".to_string(),
                reason: Some(format!("SSRF: {} resolved to {} ({})", dest_host, ip, reason)),
                ..
            });
            return Ok(());
        }
        Err(e) => {
            log::warn!("DNS/SSRF error for {}: {:?}", dest_host, e);
            return Ok(());
        }
    }
}
```

#### Step 3: allowed_ips Configuration

**File: `guardian-common/src/lib.rs`**

```rust
/// L7 endpoint with optional allowed_ips for SSRF override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Endpoint {
    pub host: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub rules: Vec<L7Rule>,
    #[serde(default)]
    pub binaries: Vec<String>,
    /// CIDR ranges allowed for this endpoint (overrides private IP block)
    /// e.g., ["10.86.8.0/24"] to allow a local inference server
    #[serde(default)]
    pub allowed_ips: Option<Vec<String>>,
}
```

**Config example:**

```toml
[[agents.l7_network_policy.endpoints]]
host = "inference.internal"
port = 8080
# Allow connections to this specific private subnet
allowed_ips = ["10.86.8.0/24"]
```

### 4d. Testing Strategy

1. **Unit tests**: `check_ip()` for all tiers, IPv4-mapped IPv6 unwrapping
2. **DNS rebinding test**: Mock DNS resolver returning private IP → verify block
3. **Allowed_ips test**: Verify private IP allowed when in allowlist
4. **Control plane test**: Verify port 6443 blocked even on public IP
5. **Integration test**: Agent tries `curl 169.254.169.254` → blocked

---

## 5. Binary Integrity (SHA256 TOFU)

### 5a. Motivation

Per-binary network policy (Phase 13.3) relies on `/proc/{pid}/exe` to identify
binaries. But if an attacker replaces a binary (e.g., overwrites `/usr/bin/git`
with a malicious binary), the path still matches policy. We need to verify the
binary content hasn't changed.

### 5b. Architecture

```
First connection from /usr/bin/git:
    ┌─────────────────────────────┐
    │ 1. readlink /proc/PID/exe   │
    │    → /usr/bin/git           │
    │                             │
    │ 2. stat /usr/bin/git        │
    │    → size=2847616           │
    │      mtime=1709654400.123   │
    │      ctime=1709654400.456   │
    │      dev=0x0803             │
    │      ino=1234567            │
    │                             │
    │ 3. SHA256(/usr/bin/git)     │
    │    → a1b2c3d4e5f6...       │
    │                             │
    │ 4. Cache: /usr/bin/git →    │
    │    { hash, fingerprint }    │
    │                             │
    │ 5. ALLOW (first use)        │
    └─────────────────────────────┘

Second connection from /usr/bin/git (binary replaced):
    ┌─────────────────────────────┐
    │ 1. readlink → /usr/bin/git  │
    │                             │
    │ 2. stat → size CHANGED!     │
    │    (or ctime, or ino)       │
    │                             │
    │ 3. Re-hash: SHA256(new file)│
    │    → ffee0011aabb...        │
    │                             │
    │ 4. a1b2c3d4 ≠ ffee0011     │
    │    → INTEGRITY VIOLATION    │
    │                             │
    │ 5. DENY + alert             │
    └─────────────────────────────┘
```

### 5c. Implementation Steps

#### Step 1: Binary Identity Cache

**New file: `guardian-proxy/src/integrity.rs`**

```rust
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Filesystem metadata fingerprint — fast check before rehashing
#[derive(Debug, Clone, PartialEq)]
struct FileFingerprint {
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    dev: u64,
    ino: u64,
}

impl FileFingerprint {
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            size: meta.size(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedBinary {
    hash: String,                   // Hex-encoded SHA256
    fingerprint: FileFingerprint,
}

/// TOFU binary integrity cache
pub struct BinaryIntegrityCache {
    cache: Mutex<HashMap<PathBuf, CachedBinary>>,
    max_entries: usize,
}

/// Result of integrity verification
#[derive(Debug)]
pub enum IntegrityResult {
    /// First use — hash recorded as baseline
    FirstUse { hash: String },
    /// Fingerprint unchanged — cached hash returned (fast path)
    Cached { hash: String },
    /// Fingerprint changed but hash matches (e.g., `touch` without content change)
    Rehashed { hash: String },
    /// VIOLATION: hash changed since first use
    Violation {
        path: PathBuf,
        cached_hash: String,
        current_hash: String,
    },
}

impl BinaryIntegrityCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Verify binary integrity. Returns the SHA256 hash or an integrity violation.
    pub fn verify(&self, path: &Path) -> anyhow::Result<IntegrityResult> {
        let meta = std::fs::metadata(path)?;
        let current_fp = FileFingerprint::from_metadata(&meta);

        let mut cache = self.cache.lock().unwrap();

        if let Some(cached) = cache.get(path) {
            if cached.fingerprint == current_fp {
                // Fast path: fingerprint unchanged, trust cached hash
                return Ok(IntegrityResult::Cached {
                    hash: cached.hash.clone(),
                });
            }

            // Fingerprint changed — must rehash
            let current_hash = sha256_file(path)?;

            if current_hash != cached.hash {
                // INTEGRITY VIOLATION
                return Ok(IntegrityResult::Violation {
                    path: path.to_path_buf(),
                    cached_hash: cached.hash.clone(),
                    current_hash,
                });
            }

            // Hash matches despite fingerprint change (e.g., touch without edit)
            // Update fingerprint to avoid rehashing next time
            cache.get_mut(path).unwrap().fingerprint = current_fp;
            return Ok(IntegrityResult::Rehashed { hash: current_hash });
        }

        // First use — compute hash and cache
        let hash = sha256_file(path)?;

        // Evict if cache full
        if cache.len() >= self.max_entries {
            // Simple strategy: clear everything
            // A production implementation would use LRU
            cache.clear();
        }

        cache.insert(path.to_path_buf(), CachedBinary {
            hash: hash.clone(),
            fingerprint: current_fp,
        });

        Ok(IntegrityResult::FirstUse { hash })
    }
}

/// Compute SHA256 hash of a file
fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}
```

**New dependency in `guardian-proxy/Cargo.toml`:**

```toml
sha2 = "0.10"
hex = "0.4"
```

#### Step 2: Integrate with Process Identity

**File: `guardian-proxy/src/procfs.rs`**

```rust
impl ProcessIdentity {
    /// Verify integrity of this binary and all ancestors
    pub fn verify_integrity(
        &mut self,
        cache: &BinaryIntegrityCache,
    ) -> anyhow::Result<()> {
        // Check main binary
        match cache.verify(&self.binary_path)? {
            IntegrityResult::Violation { path, cached_hash, current_hash } => {
                anyhow::bail!(
                    "Binary integrity violation: {} hash changed ({} → {})",
                    path.display(), &cached_hash[..12], &current_hash[..12]
                );
            }
            IntegrityResult::FirstUse { hash } | IntegrityResult::Cached { hash }
            | IntegrityResult::Rehashed { hash } => {
                self.binary_sha256 = hash;
            }
        }

        // Check each ancestor binary
        for ancestor in &self.ancestors {
            if let IntegrityResult::Violation { path, cached_hash, current_hash } =
                cache.verify(ancestor)?
            {
                anyhow::bail!(
                    "Ancestor integrity violation: {} hash changed ({} → {})",
                    path.display(), &cached_hash[..12], &current_hash[..12]
                );
            }
        }

        Ok(())
    }
}
```

#### Step 3: Integrate into Proxy

**File: `guardian-proxy/src/main.rs`**

```rust
// Global integrity cache (shared across all connections)
lazy_static::lazy_static! {
    static ref INTEGRITY_CACHE: BinaryIntegrityCache = BinaryIntegrityCache::new(512);
}

async fn handle_connection(/* ... */) -> anyhow::Result<()> {
    // ... after resolving process identity ...

    // Verify binary integrity (TOFU)
    if let Err(e) = identity.verify_integrity(&INTEGRITY_CACHE) {
        log::error!("BINARY INTEGRITY VIOLATION: {}", e);
        send_l7_event(L7NetworkEvent {
            action: "deny".to_string(),
            reason: Some(format!("integrity: {}", e)),
            binary_path: Some(identity.binary_path.to_string_lossy().to_string()),
            binary_sha256: Some(identity.binary_sha256.clone()),
            ..
        });
        // TODO: Consider alerting the daemon for immediate investigation
        return Ok(());
    }

    // Continue with L7 inspection...
}
```

### 5d. Dashboard Integration

Add a new section to the events page showing binary integrity events:

**File: `guardian/src/dashboard/routes/pages.rs`**

Display L7 events including binary integrity violations in the existing events
table. Integrity violations should be highlighted with `Critical` severity.

### 5e. Testing Strategy

1. **Unit tests**: `BinaryIntegrityCache` — first use, cached, rehash, violation
2. **Fingerprint test**: Modify mtime only → verify no violation (content same)
3. **Replace test**: Replace binary → verify violation detected
4. **ctime test**: Replace binary + restore mtime → verify ctime catches it
5. **Performance test**: Verify fingerprint fast path avoids SHA256 on every call
6. **Ancestor test**: Replace ancestor binary → verify violation propagates

---

## 6. Cross-Platform Container Mode

### 6a. Motivation

Guardian Shell requires Linux with kernel 5.13+ and BPF support. Most developers
use macOS. OpenShell solves this by running everything inside Docker.

### 6b. Architecture

We add an optional `guardian-container` mode that wraps Guardian Shell in a
Docker container. This is a deployment layer, not a code change.

```
macOS / Windows Host
    │
    ▼
┌──────────────────────────────────────────────────┐
│  Docker Container (Linux, kernel 6.x)            │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  guardian daemon (eBPF, Landlock, seccomp)  │  │
│  │  guardian-launch (cgroup sandbox)           │  │
│  │  guardian-proxy (L7 inspection)             │  │
│  │  guardian-ctl (CLI)                         │  │
│  │  Dashboard (web UI on mapped port)          │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  Volume mounts:                                  │
│  - /workspace → host project directory           │
│  - /config → host config.toml                    │
│                                                  │
│  Port mappings:                                  │
│  - 8080 → dashboard                              │
│  - 9090 → Prometheus metrics                     │
└──────────────────────────────────────────────────┘
```

### 6c. Implementation Steps

#### Step 1: Dockerfile

**New file: `Dockerfile`**

```dockerfile
# Stage 1: Build eBPF + userspace
FROM rust:1.82-bookworm AS builder

RUN apt-get update && apt-get install -y \
    llvm-dev clang libelf-dev linux-headers-generic \
    pkg-config libssl-dev

RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo install bpf-linker

WORKDIR /build
COPY . .

RUN cargo xtask build-ebpf --release
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libelf1 iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/guardian /usr/local/bin/
COPY --from=builder /build/target/release/guardian-launch /usr/local/bin/
COPY --from=builder /build/target/release/guardian-ctl /usr/local/bin/
COPY --from=builder /build/target/release/guardian-proxy /usr/local/bin/

# Default config
COPY configs/recommended.toml /etc/guardian/config.toml

# Dashboard port
EXPOSE 8080
# Prometheus metrics
EXPOSE 9090

VOLUME ["/workspace", "/etc/guardian"]

ENTRYPOINT ["guardian", "--config", "/etc/guardian/config.toml"]
```

#### Step 2: Docker Compose

**New file: `docker-compose.yml`**

```yaml
version: "3.8"
services:
  guardian:
    build: .
    privileged: true                    # Required for eBPF + cgroups
    pid: host                           # Required for /proc access
    volumes:
      - ./config.toml:/etc/guardian/config.toml:ro
      - /sys/fs/cgroup:/sys/fs/cgroup   # Required for cgroup management
      - /sys/kernel/debug:/sys/kernel/debug:ro  # Required for tracepoints
      - ./workspace:/workspace          # Agent workspace
    ports:
      - "8080:8080"                     # Dashboard
      - "9090:9090"                     # Prometheus
    environment:
      - RUST_LOG=info
```

#### Step 3: Launcher Script

**New file: `scripts/guardian-docker.sh`**

```bash
#!/bin/bash
# Launch Guardian Shell in Docker — works on macOS, Windows (WSL2), Linux
set -euo pipefail

CONFIG="${1:-config.toml}"
WORKSPACE="${2:-.}"

echo "Starting Guardian Shell in Docker..."
echo "  Config: $CONFIG"
echo "  Workspace: $WORKSPACE"
echo "  Dashboard: http://localhost:8080"

docker run -d \
    --name guardian-shell \
    --privileged \
    --pid=host \
    -v "$(realpath "$CONFIG"):/etc/guardian/config.toml:ro" \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v "$(realpath "$WORKSPACE"):/workspace" \
    -p 8080:8080 \
    -p 9090:9090 \
    -e RUST_LOG=info \
    guardian-shell:latest

echo "Guardian Shell running. Dashboard at http://localhost:8080"
echo "To launch an agent inside: docker exec guardian-shell guardian-launch --name my-agent -- bash"
echo "To stop: docker stop guardian-shell && docker rm guardian-shell"
```

### 6d. Limitations

- Requires `--privileged` (eBPF needs `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`)
- Requires `--pid=host` for `/proc` access across containers
- On macOS Docker Desktop, eBPF runs against the Docker VM's kernel, not the host
- Performance overhead from container layer (minimal for eBPF, noticeable for I/O)
- Dashboard accessible only via port mapping (no native browser integration)
- Agent workspace is a volume mount — file events show container paths

### 6e. Testing Strategy

1. **Build test**: `docker build .` succeeds
2. **Startup test**: Container starts, eBPF loads, dashboard accessible
3. **Agent test**: `docker exec` guardian-launch, verify file monitoring works
4. **macOS test**: Docker Desktop on Apple Silicon, verify eBPF attaches
5. **Cross-platform CI**: GitHub Actions matrix (ubuntu, macos) with Docker

---

## 7. Implementation Order

Features have dependencies. Here is the recommended order:

```
Phase 13a: SSRF Prevention (ssrf.rs)
    │       No dependencies. Pure utility module.
    │       Estimated effort: Small
    │
Phase 13b: Binary Integrity TOFU (integrity.rs)
    │       No dependencies. Pure utility module.
    │       Estimated effort: Small
    │
Phase 13c: L7 Network Inspection (guardian-proxy crate)
    │       New crate. Uses 13a (SSRF) internally.
    │       Largest feature — TLS interception, HTTP parsing, proxy loop.
    │       Estimated effort: Large
    │       Dependencies: 13a
    │
Phase 13d: Per-Binary Network Policy (procfs.rs)
    │       Requires guardian-proxy (13c) for /proc inspection at proxy.
    │       Integrates 13b (integrity) for TOFU verification.
    │       Estimated effort: Medium
    │       Dependencies: 13b, 13c
    │
Phase 13e: Credential Isolation (credentials.rs)
    │       Requires guardian-proxy (13c) for header substitution.
    │       Requires guardian-launch changes for env replacement.
    │       Estimated effort: Medium
    │       Dependencies: 13c
    │
Phase 13f: Cross-Platform Container Mode (Dockerfile)
            No code dependencies. Packaging layer.
            Can be done in parallel with any phase.
            Estimated effort: Small
```

**Dependency graph:**

```
13a (SSRF) ──────────┐
                      ├──► 13c (L7 Proxy) ──┬──► 13d (Per-Binary)
13b (Integrity) ─────┘                      │
                                             ├──► 13e (Credentials)
                                             │
13f (Container) ◄── independent ────────────┘
```

**Minimum viable Phase 13**: Implement 13a + 13c (L7 proxy with SSRF prevention).
This delivers the highest-value feature (L7 inspection) with essential safety
(SSRF prevention). Per-binary policy, integrity, and credentials can follow
incrementally.

---

## 8. Risk Assessment

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **iptables REDIRECT conflicts with eBPF** | Agent connections double-intercepted (eBPF tracepoint + proxy) | Ensure eBPF port-level check runs first; proxy handles L7 only. Both layers complement rather than conflict. |
| **TLS interception breaks certificate pinning** | Some agents/tools pin certificates and reject the ephemeral CA | Add `tls: skip` option per endpoint to bypass TLS interception (raw tunnel mode). Document known pinning tools. |
| **Proxy crash = agent network blackout** | If guardian-proxy dies, iptables REDIRECT still active but proxy unreachable → all connections fail | guardian-launch monitors proxy PID; if proxy exits, remove iptables rules and log warning. Consider supervisor restart. |
| **Performance overhead** | TLS termination + re-encryption adds latency | Benchmark. Skip L7 for high-throughput endpoints (raw tunnel). Consider connection pooling for repeated upstream hosts. |
| **SHA256 on large binaries is slow** | First-use hash of 100MB+ binaries blocks connection | Fingerprint fast path avoids re-hashing. Consider async hashing with connection held. Set file size limit for hashing. |
| **`/proc` race conditions** | PID reuse between socket lookup and /proc read | Use pidfd (Linux 5.3+) for race-free PID references where available. Short window makes this low-probability. |

### Security Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Proxy runs with network access outside sandbox** | Compromised proxy = full network access | Proxy runs inside the cgroup but before Landlock. Apply minimal Landlock to proxy (needs /proc + network only). |
| **Credential mapping file readable by agent** | If agent gains root, can read proxy's credential store | File is 0600 root-owned. NO_NEW_PRIVS prevents setuid escalation. Seccomp blocks dangerous syscalls. Consider memfd for in-memory-only storage. |
| **Ephemeral CA private key in proxy memory** | Memory dump exposes CA key → mint certs for any host | CA is per-sandbox, valid 24h only. Sandbox termination destroys the key. Acceptable risk for the protection it provides. |
| **SO_ORIGINAL_DST bypass** | Agent connects directly to 127.0.0.1:13128 and spoofs destination | Proxy validates that SO_ORIGINAL_DST differs from its own listen address. Log and deny direct proxy connections. |

### Architectural Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Scope creep toward OpenShell** | Guardian Shell becomes a container orchestrator | Stay process-level. L7 proxy is the only new component. No K8s, no pod scheduling, no etcd. |
| **Maintenance burden of proxy crate** | New crate to maintain: TLS, HTTP parsing, proxy logic | Use well-tested crates (rustls, httparse). Keep proxy simple — no HTTP/2, no WebSocket inspection initially. |
| **Two enforcement paths** | eBPF enforces L4, proxy enforces L7 → confusion about which blocked a connection | Clear logging: eBPF events say "L4", proxy events say "L7". Dashboard shows both with distinct labels. |

---

*Last updated: 2026-03-25*
