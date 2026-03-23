# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.11.0  | Yes                |
| < 0.11.0| No                 |

## Reporting a Vulnerability

We take the security of Guardian Shell seriously. If you discover a security
vulnerability, please report it responsibly.

### How to Report

- **Email:** Send details to **security@guardianshell.dev**
- **GitHub:** Open a [private security advisory](https://github.com/guardianshell/guardian_shell/security/advisories/new) on the repository

### What to Include

- A clear description of the vulnerability
- Steps to reproduce the issue
- The affected component (eBPF program, daemon, launcher, dashboard, IPC, etc.)
- The potential impact (privilege escalation, policy bypass, denial of service, etc.)
- Any suggested fix or mitigation, if you have one
- Your environment details (kernel version, distribution, Guardian Shell version)

### Response Timeline

- **48 hours:** We will acknowledge receipt of your report
- **7 days:** We will provide an initial assessment of the vulnerability
- **30 days:** We aim to release a fix for confirmed vulnerabilities

For critical vulnerabilities (e.g., eBPF policy bypass, sandbox escape), we will
prioritize a fix and may issue an out-of-band release.

### What NOT to Do

- **Do not open a public GitHub issue** for security vulnerabilities
- **Do not post details** on public forums, mailing lists, or social media before a fix is available
- **Do not exploit** the vulnerability beyond what is necessary to demonstrate it

### Credit

We believe in recognizing security researchers for their contributions. If you
report a valid vulnerability, we will:

- Credit you in the release notes (unless you prefer to remain anonymous)
- Add you to our security acknowledgments
- Work with you on coordinated disclosure timing

Thank you for helping keep Guardian Shell and its users safe.
