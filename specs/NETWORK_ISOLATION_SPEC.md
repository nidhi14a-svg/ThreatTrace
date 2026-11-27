# Network Isolation Specification

- **Document:** `specs/NETWORK_ISOLATION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 4, Task 4.5)
- **Version:** 1.0.0

---

## 1. Network Perimeter & Isolation Strategy

Scanners operate on untrusted user code. To prevent exfiltration of intellectual property, secret validation callbacks, command-and-control communication, or internal lateral movement across Docker networks, the scanner worker environment is strictly isolated.

```
       [ INTERNET ]
            |
            | (port 3000)
            v
     +--------------+
     |   frontend   |
     +--------------+
            | (app-net: standard bridge)
            v
     +--------------+     (outbound HTTPS only for Gemini AI)
     |   backend    | -----------------------------------------> [ Google Gemini API ]
     +--------------+
      /            \
     / (db-net)     \ (scanner-net)
    / [internal]     \ [internal]
   v                  v
+----------+      +----------+
| mongodb  |      | scanner  |  <--- STRICTLY AIR-GAPPED:
+----------+      +----------+       - NO Internet Egress
                                     - NO Access to MongoDB
                                     - NO Access to Frontend
```

---

## 2. Ingress & Egress Rules by Container

| Container | Inbound Traffic Allowed | Outbound Traffic Allowed | Internal Only Flag |
|---|---|---|---|
| **`frontend`** | Host: Port 3000 (User browser) | `backend:8000` on `app-net` | `false` |
| **`backend`** | Host: 127.0.0.1:8000, `frontend` on `app-net` | `mongodb:27017` on `db-net`, `scanner` on `scanner-net`, AI API HTTPS (outbound) | `false` |
| **`mongodb`** | `backend` on `db-net` | None | `true` |
| **`scanner`** | `backend` on `scanner-net` | None (No outbound egress) | `true` |

---

## 3. Tool Offline Mode Safeguards

1. **OSV-Scanner:**
   - Must be invoked with `--offline` or lockfile inspection mode.
   - Does not query live vulnerability feeds during container runs.
2. **Semgrep:**
   - Must run with `--disable-version-check`, `--metrics=off`, and local rulesets only (`--config=p/ci` or local rules).
3. **Bandit:**
   - Runs strictly in-memory offline AST analysis.
4. **Gitleaks:**
   - Runs strictly local file and commit regex analysis with `--no-git` on extracted directories.
5. **Custom Rules:**
   - Executes purely within Python process with zero socket creation.

---

## 4. Container Prohibitions

1. **Direct Database Access Prohibited:**
   - The scanner worker has no IP route to `mongodb:27017`. Even if a scanner engine were compromised via parser exploit, it cannot read, modify, or drop the MongoDB database.
2. **Docker Socket Prohibited:**
   - `/var/run/docker.sock` is NEVER mounted into any container.
3. **No Raw Sockets:**
   - `CAP_NET_RAW` is dropped, prohibiting raw packet creation and network sniffing.
