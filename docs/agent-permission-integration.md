# Guardian Shell: Agent Permission Integration Guide

This document shows how to integrate LLM agents with Guardian Shell's
interactive permission system (Phase 6). It covers:

1. A **sample system prompt** to teach an LLM agent to request permissions
2. A **JavaScript tool-call implementation** for agent frameworks

---

## How It Works

There are **two ways** an agent can get temporary access:

### A. Direct Grant (no approval needed)

An operator (or script) grants access immediately using `guardian-ctl grant`.
No dashboard or human approval step — the grant is applied instantly.

```bash
# File access grant (default)
guardian-ctl grant -n my-agent -p "/etc/hosts" -d 60

# Exec grant (use -t exec)
guardian-ctl grant -n my-agent -p "/usr/bin/curl" -d 60 -t exec
```

This is useful for pre-authorized access, scripts, or CI/CD pipelines.

### B. Permission Request (requires human approval)

When an agent doesn't have pre-authorized access, it can request permission
via `guardian-ctl request-permission`. The request appears on the Guardian
dashboard where a human approves or denies it. The agent blocks until the
decision is made (up to 120s timeout).

```
Agent gets EACCES ──> guardian-ctl request-permission ──> Daemon (Unix socket)
                                                              │
                                                              ▼
Agent unblocks <── decision sent back <── Human approves/denies on Dashboard
```

### Summary: All Grant Methods

| Method | Grant Types | Human Approval | Use Case |
|--------|-------------|----------------|----------|
| `guardian-ctl grant` | file, exec (`-t exec`) | No (immediate) | Operator/script pre-grants access |
| `guardian-ctl request-permission` | file, exec (`-t exec`) | Yes (dashboard) | Agent asks, human decides |
| Dashboard UI (agents page) | file, exec | No (immediate) | Operator grants via browser |

---

## 1. Sample System Prompt for LLM Agents

Add the following to your agent's system prompt (adjust paths as needed):

```
### Guardian Shell: File & Command Permissions

You are running inside a Guardian Shell sandbox. Your file and command access
is restricted by security policy.

**When you get a "Permission denied" (EACCES) error:**

1. Do NOT retry the same command immediately — it will fail again.
2. Request permission using the `request_permission` tool.
3. Wait for the human operator to approve or deny your request.
4. If approved, retry the original command. The grant is temporary (typically
   60s–3600s), so act promptly.
5. If denied, find an alternative approach or explain to the user why you need
   that access.

**When to proactively request permission (before hitting an error):**

- Before reading sensitive files: /etc/shadow, ~/.ssh/*, ~/.aws/*, .env files
- Before executing destructive commands: rm, dd, mkfs, systemctl
- Before accessing files outside your allowed directories

**request_permission tool parameters:**

| Parameter       | Required | Description                                    |
|-----------------|----------|------------------------------------------------|
| agent_name      | Yes      | Your agent name (must match your registered name) |
| resource_type   | Yes      | "file" (for file access) or "exec" (for command execution) |
| resource_path   | Yes      | Full path to the file or command (e.g., "/etc/passwd", "/usr/bin/curl") |
| justification   | No       | Brief explanation of why you need this access   |

**Example usage:**

If `cat /etc/hosts` fails with "Permission denied":
  → Call request_permission with:
    - agent_name: "my-agent"
    - resource_type: "file"
    - resource_path: "/etc/hosts"
    - justification: "Need to resolve hostnames for network configuration"

**Important rules:**
- Always provide a justification — it helps the human decide faster.
- Never request access to paths you don't actually need.
- If denied, respect the decision. Do not re-request the same resource
  unless circumstances have changed.
- Grants are temporary. If your grant expires and you need access again,
  submit a new request.
```

---

## 2. JavaScript Tool-Call Implementation

### 2a. Using `guardian-ctl` CLI (Simple)

This approach shells out to `guardian-ctl`. Works with any Node.js agent.

```javascript
const { execSync } = require("child_process");

/**
 * Tool definition: grant temporary access directly (no human approval).
 * Use this when the agent orchestrator has authority to grant access.
 */
const directGrantTool = {
  type: "function",
  function: {
    name: "grant_access",
    description:
      "Grant temporary file or exec access to an agent immediately " +
      "(no human approval required). Use for pre-authorized access.",
    parameters: {
      type: "object",
      properties: {
        agent_name: {
          type: "string",
          description: "The registered agent name in Guardian Shell.",
        },
        path: {
          type: "string",
          description:
            "Absolute path to the file or executable (e.g., /etc/hosts, /usr/bin/curl).",
        },
        duration: {
          type: "number",
          description: "Grant duration in seconds.",
        },
        grant_type: {
          type: "string",
          enum: ["file", "exec"],
          description:
            '"file" for file access (default), "exec" for command execution.',
        },
      },
      required: ["agent_name", "path", "duration"],
    },
  },
};

/**
 * Execute the grant_access tool call.
 *
 * @param {object} args - Tool call arguments from the LLM.
 * @param {string} [ctlPath="guardian-ctl"] - Path to guardian-ctl binary.
 * @returns {{ success: boolean, message: string }}
 */
function handleDirectGrant(args, ctlPath = "guardian-ctl") {
  const cmd = [
    ctlPath,
    "grant",
    "--name", args.agent_name,
    "--path", args.path,
    "--duration", String(args.duration),
  ];

  if (args.grant_type === "exec") {
    cmd.push("--grant-type", "exec");
  }

  try {
    const stdout = execSync(cmd.join(" "), {
      timeout: 10_000,
      encoding: "utf-8",
    });
    return { success: true, message: stdout.trim() };
  } catch (err) {
    return {
      success: false,
      message: err.stderr?.toString() || err.message,
    };
  }
}

/**
 * Tool definition: request permission (requires human approval via dashboard).
 */
const requestPermissionTool = {
  type: "function",
  function: {
    name: "request_permission",
    description:
      "Request temporary permission for a file or command that is currently " +
      "blocked by Guardian Shell. Blocks until a human approves or denies " +
      "the request (up to 120s timeout).",
    parameters: {
      type: "object",
      properties: {
        agent_name: {
          type: "string",
          description: "The registered agent name in Guardian Shell.",
        },
        resource_type: {
          type: "string",
          enum: ["file", "exec"],
          description:
            '"file" for file access, "exec" for command execution.',
        },
        resource_path: {
          type: "string",
          description:
            "Absolute path to the file or executable (e.g., /etc/passwd).",
        },
        justification: {
          type: "string",
          description: "Brief explanation of why this access is needed.",
        },
      },
      required: ["agent_name", "resource_type", "resource_path"],
    },
  },
};

/**
 * Execute the request_permission tool call.
 *
 * @param {object} args - Tool call arguments from the LLM.
 * @param {string} [socketPath="/run/guardian.sock"] - Guardian daemon socket.
 * @param {string} [ctlPath="guardian-ctl"] - Path to guardian-ctl binary.
 * @returns {{ approved: boolean, reason: string, grantDurationSecs?: number }}
 */
function handleRequestPermission(args, socketPath, ctlPath = "guardian-ctl") {
  const cmd = [
    ctlPath,
    "request-permission",
    "--name", args.agent_name,
    "--resource-type", args.resource_type,
    "--path", args.resource_path,
  ];

  if (socketPath) {
    cmd.push("--socket", socketPath);
  }

  if (args.justification) {
    cmd.push("--justification", args.justification);
  }

  try {
    const stdout = execSync(cmd.join(" "), {
      timeout: 180_000, // 180s (daemon timeout is 120s)
      encoding: "utf-8",
    });

    // guardian-ctl prints "APPROVED: <reason> (granted for <N>s)"
    const match = stdout.match(/APPROVED:\s*(.+?)\s*\(granted for (\d+)s\)/);
    return {
      approved: true,
      reason: match ? match[1] : stdout.trim(),
      grantDurationSecs: match ? parseInt(match[2], 10) : undefined,
    };
  } catch (err) {
    // Exit code 1 = denied, other codes = error
    const stderr = err.stderr?.toString() || "";
    const stdout = err.stdout?.toString() || "";
    const denyMatch = stdout.match(/DENIED:\s*(.+)/);

    return {
      approved: false,
      reason: denyMatch ? denyMatch[1] : stderr || "Request denied or timed out",
    };
  }
}

module.exports = {
  directGrantTool,
  handleDirectGrant,
  requestPermissionTool,
  handleRequestPermission,
};
```

### 2b. Using Unix Socket Directly (No CLI dependency)

This approach speaks the Guardian IPC protocol directly over the Unix socket.
Useful when `guardian-ctl` is not installed or you want tighter integration.

```javascript
const net = require("net");

/**
 * Send a permission request directly to the Guardian daemon via Unix socket.
 * Uses the length-prefixed JSON IPC protocol (4-byte big-endian length + JSON).
 *
 * @param {object} options
 * @param {string} options.agentName - Registered agent name.
 * @param {string} options.resourceType - "file" or "exec".
 * @param {string} options.resourcePath - Absolute path to resource.
 * @param {string} [options.justification] - Why access is needed.
 * @param {string} [options.socketPath="/run/guardian.sock"] - Daemon socket path.
 * @returns {Promise<{ approved: boolean, reason: string, grantDurationSecs?: number }>}
 */
function requestPermission({
  agentName,
  resourceType,
  resourcePath,
  justification,
  socketPath = "/run/guardian.sock",
}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    socket.setTimeout(180_000); // 180s total timeout

    // Build the IPC request (matches guardian-common IpcRequest::RequestPermission)
    const request = {
      type: "request_permission",
      agent_name: agentName,
      resource_type: resourceType,
      resource_path: resourcePath,
    };
    if (justification) {
      request.justification = justification;
    }

    socket.on("connect", () => {
      // Send length-prefixed JSON (4-byte big-endian length header)
      const jsonBytes = Buffer.from(JSON.stringify(request), "utf-8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(jsonBytes.length);
      socket.write(Buffer.concat([header, jsonBytes]));
    });

    // Accumulate response data
    const chunks = [];
    socket.on("data", (chunk) => chunks.push(chunk));

    socket.on("end", () => {
      try {
        const data = Buffer.concat(chunks);
        if (data.length < 4) {
          return reject(new Error("Invalid response: too short"));
        }

        // Parse length-prefixed JSON response
        const responseLen = data.readUInt32BE(0);
        const responseJson = data.slice(4, 4 + responseLen).toString("utf-8");
        const response = JSON.parse(responseJson);

        // response.type is "permission_decision", "error", or "ack"
        if (response.type === "permission_decision") {
          resolve({
            approved: response.approved,
            reason: response.reason,
            grantDurationSecs: response.grant_duration_secs,
          });
        } else if (response.type === "error") {
          resolve({
            approved: false,
            reason: response.message,
          });
        } else {
          resolve({
            approved: false,
            reason: `Unexpected response type: ${response.type}`,
          });
        }
      } catch (err) {
        reject(new Error(`Failed to parse response: ${err.message}`));
      }
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ approved: false, reason: "Request timed out" });
    });

    socket.on("error", (err) => {
      reject(new Error(`Socket error: ${err.message}. Is the Guardian daemon running?`));
    });
  });
}

/**
 * Grant temporary access directly via Unix socket (no human approval).
 *
 * @param {object} options
 * @param {string} options.agentName - Registered agent name.
 * @param {string} options.path - Absolute path to file or executable.
 * @param {number} options.durationSecs - Grant duration in seconds.
 * @param {string} [options.grantType="file"] - "file" or "exec".
 * @param {string} [options.socketPath="/run/guardian.sock"] - Daemon socket path.
 * @returns {Promise<{ success: boolean, message: string }>}
 */
function grantAccess({
  agentName,
  path,
  durationSecs,
  grantType = "file",
  socketPath = "/run/guardian.sock",
}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    socket.setTimeout(10_000);

    const request = {
      type: "grant",
      agent_name: agentName,
      path: path,
      duration_secs: durationSecs,
      grant_type: grantType,
    };

    socket.on("connect", () => {
      const jsonBytes = Buffer.from(JSON.stringify(request), "utf-8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(jsonBytes.length);
      socket.write(Buffer.concat([header, jsonBytes]));
    });

    const chunks = [];
    socket.on("data", (chunk) => chunks.push(chunk));

    socket.on("end", () => {
      try {
        const data = Buffer.concat(chunks);
        if (data.length < 4) {
          return reject(new Error("Invalid response: too short"));
        }
        const responseLen = data.readUInt32BE(0);
        const responseJson = data.slice(4, 4 + responseLen).toString("utf-8");
        const response = JSON.parse(responseJson);

        if (response.type === "ack") {
          resolve({ success: true, message: "Grant applied" });
        } else if (response.type === "error") {
          resolve({ success: false, message: response.message });
        } else {
          resolve({ success: false, message: `Unexpected: ${response.type}` });
        }
      } catch (err) {
        reject(new Error(`Failed to parse response: ${err.message}`));
      }
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ success: false, message: "Request timed out" });
    });

    socket.on("error", (err) => {
      reject(new Error(`Socket error: ${err.message}. Is the Guardian daemon running?`));
    });
  });
}

module.exports = { requestPermission, grantAccess };
```

### 2c. Full Agent Loop Example

Putting it all together — an agent that retries operations after getting permission:

```javascript
const { execSync } = require("child_process");
const { handleRequestPermission } = require("./guardian-permission-cli");
// Or: const { requestPermission } = require("./guardian-permission-socket");

const AGENT_NAME = "my-agent";

/**
 * Execute a shell command with automatic permission retry.
 * If the command fails with EACCES, request permission and retry once.
 *
 * @param {string} command - Shell command to execute.
 * @param {string} resourceType - "file" or "exec".
 * @param {string} resourcePath - The path being accessed.
 * @param {string} justification - Why the agent needs this access.
 * @returns {string} Command output on success.
 * @throws {Error} If denied or command fails for non-permission reasons.
 */
function executeWithPermissionRetry(command, resourceType, resourcePath, justification) {
  try {
    return execSync(command, { encoding: "utf-8" });
  } catch (err) {
    const isPermissionError =
      err.stderr?.includes("Permission denied") ||
      err.stderr?.includes("EACCES") ||
      err.status === 1; // Common for permission-denied exits

    if (!isPermissionError) {
      throw err; // Not a permission issue, re-throw
    }

    console.log(`[Guardian] Access denied for ${resourcePath}, requesting permission...`);

    const result = handleRequestPermission({
      agent_name: AGENT_NAME,
      resource_type: resourceType,
      resource_path: resourcePath,
      justification: justification,
    });

    if (!result.approved) {
      throw new Error(
        `Permission denied by operator: ${result.reason}. ` +
        `Find an alternative approach for: ${command}`
      );
    }

    console.log(
      `[Guardian] Permission granted for ${result.grantDurationSecs}s, retrying...`
    );

    // Retry now that we have temporary access
    return execSync(command, { encoding: "utf-8" });
  }
}

// --- Usage ---
try {
  const hosts = executeWithPermissionRetry(
    "cat /etc/hosts",
    "file",
    "/etc/hosts",
    "Need to check DNS resolution entries"
  );
  console.log(hosts);
} catch (err) {
  console.error("Failed:", err.message);
}
```

---

## 3. IPC Protocol Reference

Guardian Shell uses **length-prefixed JSON** over a Unix domain socket
(`/run/guardian.sock` by default).

### Wire Format

```
[4 bytes: message length (big-endian uint32)] [N bytes: JSON payload]
```

### Request Payload: Direct Grant

```json
{
  "type": "grant",
  "agent_name": "my-agent",
  "path": "/usr/bin/curl",
  "duration_secs": 60,
  "grant_type": "exec"
}
```

`grant_type` is `"file"` (default) or `"exec"`.

### Request Payload: Permission Request

```json
{
  "type": "request_permission",
  "agent_name": "my-agent",
  "resource_type": "file",
  "resource_path": "/etc/hosts",
  "justification": "Need to check DNS entries"
}
```

### Response Payload (Approved)

```json
{
  "type": "permission_decision",
  "approved": true,
  "reason": "Approved by admin",
  "grant_duration_secs": 300
}
```

### Response Payload (Denied)

```json
{
  "type": "permission_decision",
  "approved": false,
  "reason": "Denied by admin",
  "grant_duration_secs": null
}
```

### Response Payload (Error)

```json
{
  "type": "error",
  "message": "Agent 'my-agent' not found"
}
```

---

## 4. Integration Checklist

- [ ] Agent is launched via `guardian-launch --name <agent-name> -- <command>`
- [ ] Agent name in permission requests matches the name used in `guardian-launch`
- [ ] System prompt instructs the agent to call `request_permission` on `EACCES`
- [ ] Guardian dashboard is enabled in `config.toml` (`[dashboard] enabled = true`)
- [ ] A human operator is monitoring the dashboard to approve/deny requests
- [ ] Agent handles both "approved" and "denied" responses gracefully
- [ ] Agent acts within the grant window (grants are temporary)
