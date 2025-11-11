# Odoo IoT Networking and Connectivity Analysis

**Research Summary – Windows Virtual IoT + Odoo PoS (Cloud)**

---

## Table of Contents

| Section | Topic |
|----------|-------|
| [1. Overview](#1-overview) | Overview of Odoo IoT architecture and research context |
| [2. Certificate and TLS Context](#2-certificate-and-tls-context) | Let’s Encrypt wildcard certificates and trust scope |
| [3. Communication Topology](#3-communication-topology) | Logical network flow between Odoo Cloud, PoS, and IoT device |
| [4. Hostname, Certificate Lifecycle, and Local Reverse Proxy Trust Model](#4-hostname-certificate-lifecycle-and-local-reverse-proxy-trust-model) | Hostname encoding, DNS behavior, certificate lifecycle, nginx proxy, and trust chain |
| [5. Behavior With and Without WAN Connectivity](#5-behavior-with-and-without-wan-connectivity) | LAN continuity, offline operation, and renewal requirements |
| [6. Verification Steps](#6-verification-steps) | Commands and diagnostics to validate connectivity and proxy setup |
| [7. Offline Resilience and Local Resolution Options](#7-offline-resilience-and-local-resolution-options) | DNS caching, local resolvers, and host-file fallback mechanisms |
| [8. Summary of Key Findings](#8-summary-of-key-findings) | Consolidated findings across networking, TLS, and offline behavior |
| [8A. Findings on IP Change and Configuration Stability](#8a-findings-on-ip-change-and-configuration-stability) | Impact of dynamic addressing and recommendation for static IPs |
| [9. Conclusions](#9-conclusions) | Summarized implications of the analysis and key takeaways |
| [10. References](#10-references) | Official Odoo, Let’s Encrypt, and Google DNS documentation |

---

## 1. Overview

This document explains how **Odoo’s IoT infrastructure** establishes and maintains secure communication between the **cloud-hosted Odoo instance** and the **local IoT box or Windows Virtual IoT runtime**, even when operating within private LAN environments.

The findings are based on inspection of certificate contents, DNS resolution behavior, network traces, and controlled offline testing of Odoo’s Windows Virtual IoT software.

---

## 2. Certificate and TLS Context

Each Odoo IoT installation receives a **unique wildcard TLS certificate** issued by **Let’s Encrypt**, provisioned and renewed by Odoo’s cloud service.

Example certificate parameters:

| Field                     | Value                                              |
| ------------------------- | -------------------------------------------------- |
| Common Name               | `*.d73e7513.odoo-iot.com`                          |
| Issuer                    | Let’s Encrypt R12 → ISRG Root X1                   |
| Validity                  | 2025-09-23 → 2025-12-22                            |
| Subject Alternative Names | `*.d73e7513.odoo-iot.com`, `d73e7513.odoo-iot.com` |

### 2.1 Key Observation

The certificate is **globally trusted** and **domain-scoped**, not IP-scoped.
Any subdomain under `*.<variable>.odoo-iot.com` e.g. `*.d73e7513.odoo-iot.com` is valid and can be served via HTTPS/WSS locally without additional certificates.

Thus, TLS trust remains intact even when the connection happens entirely over a private LAN, as long as the hostname remains consistent.

---

## 3. Communication Topology

The Odoo IoT architecture separates concerns as follows:

```
+---------------------+           +---------------------------+
| Browser (PoS Front) |  HTTPS/WSS| Odoo Cloud (SaaS/SH)     |
|---------------------|<----------|---------------------------|
|   Loads PoS client  |           | Initiates secure channel  |
|   JS constructs URL |           | Authenticates IoT device  |
+----------^----------+           +-------------v-------------+
           |                                     
           | HTTPS/WSS (LAN or NAT loopback)
           |
+----------+--------------------------------------+
| Local IoT Device (Windows Virtual IoT)          |
|------------------------------------------------|
| Reverse Proxy (nginx-like, port 443)           |
| - Serves wildcard cert from Odoo               |
| - Accepts any subdomain of *.odoo-iot.com      |
| - Proxies HTTPS/WSS → localhost:8069 (Odoo IoT)|
| Local Odoo service                             |
| - Handles drivers (printers, scales, etc.)     |
+------------------------------------------------+
```

---

## 4. Hostname, Certificate Lifecycle, and Local Reverse Proxy Trust Model

### 4.1 Hostname Derivation and DNS Behavior

Each IoT box identifies itself by a **synthetic hostname** derived from its LAN address:

```
192-168-1-143.d73e7513.odoo-iot.com
```

Odoo’s authoritative DNS servers interpret the numeric label and return the corresponding **RFC 1918 address**:

```
> nslookup 192-168-1-143.d73e7513.odoo-iot.com 8.8.8.8
Server:  dns.google
Address: 8.8.8.8

Non-authoritative answer:
Name:    192-168-1-143.d73e7513.odoo-iot.com
Address: 192.168.1.143
```

Google DNS (8.8.8.8 / 8.8.4.4) permits such private-address responses, which is why Odoo documentation explicitly recommends using it for IoT deployments.
Once resolved, browsers reach the IoT device directly within the LAN while maintaining a **publicly trusted TLS session**.

---

### 4.2 Certificate Issuance and Renewal Workflow

During pairing, the IoT runtime calls Odoo’s endpoint
`https://www.odoo.com/odoo-enterprise/iot/x509` with the database UUID and enterprise code.
The Odoo SaaS backend:

1. **Requests a Let’s Encrypt certificate** for the device-specific FQDN encoding its private IP.
2. **Packages and returns** the signed certificate (`x509_pem`) and private key (`private_key_pem`).
3. Writes them to
   `/etc/ssl/certs/nginx-cert.crt` and `/etc/ssl/private/nginx-cert.key` (Linux) or `<nginx>\conf\nginx-cert.*` (Windows).
4. Restarts the local reverse proxy to activate the new credentials.

Renewals are automated through the same endpoint by a local scheduler.
The device never performs direct ACME challenges—**Odoo Cloud acts as a delegated ACME client and distributor**, managing issuance and proof-of-control with Let’s Encrypt.

---

### 4.3 TLS Validation and Connection Flow

When a browser accesses
`<tenant>.odoo-iot.com/`:

1. DNS resolves the hostname to the private IP.
2. The browser initiates a TLS handshake using SNI = that hostname.
3. The IoT box’s nginx listener on 443 presents `nginx-cert.crt`.
4. The certificate chains to **Let’s Encrypt R12 → ISRG Root X1** and matches the hostname.
5. Validation succeeds; the browser displays a secure lock.
6. nginx proxies decrypted traffic to `http://127.0.0.1:8069`, where the IoT runtime processes driver requests.

Result: **end-to-end TLS trust inside a private LAN** with no self-signed certificates or custom CA overhead.

---

### 4.4 Operational Dependencies

| Component / Process              | Function                                          | Managed By                     | Connectivity Need          |
| -------------------------------- | ------------------------------------------------- | ------------------------------ | -------------------------- |
| **FQDN construction**            | Encodes private IP into hostname                  | IoT runtime / Odoo Cloud       | LAN only                   |
| **Dynamic DNS (`odoo-iot.com`)** | Returns RFC 1918 A-records                        | Odoo Cloud (Authoritative DNS) | WAN for bootstrap          |
| **Certificate provisioning**     | Issues Let’s Encrypt cert via Odoo API            | Odoo Cloud / Let’s Encrypt     | WAN for issuance / renewal |
| **Local TLS termination**        | Presents cert, proxies to backend 8069            | IoT runtime (nginx)            | LAN only                   |
| **IoT backend**                  | Hardware drivers & REST API                       | IoT runtime (Odoo service)     | LAN only                   |
| **Browser client (PoS)**         | Connects to IoT FQDN via HTTPS/WSS                | User device                    | DNS resolution required    |
| **Odoo SaaS/SH**                 | Maintains device registry & certificate scheduler | Odoo Cloud                     | WAN only                   |

---

### 4.5 Security Observations

* Each device’s certificate is **publicly trusted and uniquely scoped** to its encoded hostname, binding trust to that IP within the tenant’s domain.
* Certificates are fetched securely over HTTPS from Odoo Cloud, though the local fetch disables server-certificate validation—introducing minor MITM exposure during provisioning.
* nginx is the **sole TLS termination point**; all HTTPS/WSS traffic from PoS clients terminates there.
* Once decrypted, requests are looped to `localhost:8069`.
* Recommended hardening: restrict to **TLS 1.2 / 1.3** and use Mozilla’s “Intermediate” cipher profile.

---

### 4.6 Resulting Trust Model

Odoo extends **Let’s Encrypt’s public PKI into private LANs** by mediating certificate issuance:

1. Odoo Cloud requests and renews Let’s Encrypt certificates for each IoT box.
2. Each device receives a certificate bound to its encoded LAN hostname (`192-168-x-x.{tenant}.odoo-iot.com`).
3. The IoT device terminates TLS locally using that certificate.
4. Once resolved, all HTTPS/WSS traffic between PoS frontends and IoT services stays **entirely within the LAN**, protected by globally trusted cryptography.

---

### 4.7 IP Stability and Configuration Resilience

The IoT runtime periodically reports network details via `send_alldevices()` to `/iot/setup` on the paired Odoo database.
When a device’s IP changes, the derived hostname changes as well, which can trigger creation of a new `iot.box` record.
This re-registration may desynchronize existing PoS configurations and device bindings.

**Impact summary**

* Existing PoS (`pos.config`) bindings may break or require manual reassignment.
* Multiple PoS clients can experience stale or duplicated device entries.
* Dynamic rebinding adds risk of state inconsistencies.

**Best practice**

Assign **static IPs or DHCP reservations** to all IoT boxes to ensure:

* Stable FQDN (`192-168-x-x.{tenant}.odoo-iot.com`)
* Consistent `iot.box` records
* Predictable, interruption-free PoS operation

Static addressing eliminates re-registration churn, simplifies troubleshooting, and guarantees long-term certificate validity alignment.

---

### 4.8 Local Reverse Proxy Implementation

The local nginx reverse proxy enforces the TLS lifecycle and routing model described above.
It listens on 443 (IPv4 and IPv6), presents the device’s Let’s Encrypt certificate, and forwards all HTTPS/WSS traffic to the IoT service at `127.0.0.1:8069`.

**Conceptual configuration**

```nginx
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name *.d73e7513.odoo-iot.com;

    ssl_certificate     nginx-cert.crt;
    ssl_certificate_key nginx-cert.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:
                        ECDHE-RSA-AES256-GCM-SHA384:
                        ECDHE-ECDSA-CHACHA20-POLY1305:
                        ECDHE-RSA-CHACHA20-POLY1305:
                        ECDHE-ECDSA-AES128-GCM-SHA256:
                        ECDHE-RSA-AES128-GCM-SHA256;

    location / {
        proxy_read_timeout 600s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_pass http://127.0.0.1:8069;
    }
}
```

**Observed deployment behavior**

* The Windows Virtual IoT runtime installs nginx with a minimal default configuration.
* `server_name localhost` is often specified but unused; the `default_server` context ensures all SNI hostnames are served by this certificate.
* The active certificate (`nginx-cert.crt`) is exactly the file provisioned via the `/odoo-enterprise/iot/x509` API.
* Browsers validate it successfully against the Let’s Encrypt trust chain.
* TLS 1.0 / 1.1 remain enabled for backward compatibility; modern deployments should disable them.

**Source references**

* Odoo 18 → `addons/hw_drivers/tools/helpers.py` (`check_certificate()`)
* Odoo 19 → `addons/iot_drivers/tools/helpers.py` (`check_certificate()`)

These helpers confirm the IoT box uses the same FQDN for certificate validation and connectivity testing.

---

## 5. Behavior With and Without WAN Connectivity

| Scenario                    | DNS Resolution                                                       | Certificate Validity               | HTTPS/WSS Operation                                         |
| --------------------------- | -------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------- |
| **WAN Up**                  | Google DNS resolves hostnames normally                               | Valid (Let’s Encrypt)              | All traffic flows; requests remain local or hairpin via NAT |
| **WAN Down (short outage)** | Windows DNS cache or local caching resolver retains entries          | Still valid                        | HTTPS/WSS continues; PoS can function offline               |
| **WAN Down (long outage)**  | Cached entries expire → requires local fallback (e.g., hosts update) | Still valid until expiry           | HTTPS/WSS still local if hostname resolves                  |
| **Certificate Renewal**     | Requires WAN for Let’s Encrypt ACME                                  | Odoo handles renewal automatically | No action needed locally                                    |

Thus, the WAN is required **only** for certificate renewal and DNS bootstrap;
**HTTPS and WebSocket communication between browser and IoT service are purely LAN-based** once the FQDN resolves to the private IP.

---

## 6. Verification Steps

The following commands can be used to verify resolution and proxy behavior. Of course you have to use the domain assigned to your IoT Box (in IoT module):

```bash
# Check what resolver is used
nslookup 192-168-1-143.d73e7513.odoo-iot.com

# Trace routing path (should terminate within LAN)
tracert 192-168-1-143.d73e7513.odoo-iot.com

# Confirm local reverse proxy listener
netstat -ano | findstr :443
```

Expected findings:

* DNS server = `dns.google`
* Returned address = private LAN IP (x.x.x.x) e.g. 192.168.1.143
* Listener = local process bound to 0.0.0.0:443 (Odoo IoT reverse proxy)

---

## 7. Offline Resilience and Local Resolution Options

When WAN access is unreliable, hostname resolution can be reinforced by:

1. **Windows DNS Cache** (short outages, TTL-limited)
2. **Local caching resolver** (Acrylic DNS Proxy, Technitium DNS, Unbound) configured to

   * Forward to Google DNS when WAN is up
   * Persist cached entries to disk
   * Serve expired answers when WAN is down
3. **Per-device host override script** (e.g., Python/PowerShell) that

   * Derives current LAN IP
   * Constructs FQDN (`192-168-x-x.{tenant}.odoo-iot.com`)
   * Updates `%SystemRoot%\System32\drivers\etc\hosts`
     This guarantees full offline operation, independent of DNS TTLs.

---

## 8. Summary of Key Findings

| Component                        | Function                                                | Managed By                 | Dependency                 |
| -------------------------------- | ------------------------------------------------------- | -------------------------- | -------------------------- |
| **Wildcard TLS certificate**     | Enables HTTPS/WSS trust for all IoT subdomains          | Odoo Cloud (Let’s Encrypt) | WAN only for renewal       |
| **Dynamic DNS (`odoo-iot.com`)** | Encodes private IP in hostname; resolves via Google DNS | Odoo Cloud                 | WAN for initial resolution |
| **Reverse proxy (port 443)**     | Terminates TLS and forwards to local IoT service        | Local IoT software         | LAN-only operation         |
| **IoT backend (port 8069)**      | Handles hardware drivers and API calls                  | Local IoT software         | LAN-only operation         |
| **Browser PoS client**           | Initiates HTTPS/WSS to IoT FQDN                         | User device                | DNS-dependent              |
| **Odoo SaaS/SH instance**        | Registers IoT device and manages certificates           | Odoo Cloud                 | WAN                        |

---

## 8A. Findings on IP Change and Configuration Stability

Recent inspection of Odoo 18’s IoT codebase shows that when the IoT runtime sends periodic updates via `send_alldevices()` to the `/iot/setup` route, a change in the LAN IP (and therefore the FQDN) may result in updates or, in edge cases, the creation of a new `iot.box` record. While technically extensible by overriding the route and reassigning linked PoS devices, this approach introduces significant operational complexity:

* It can disrupt established PoS Configuration-to-IoT mappings (stored in pos.config records), since device bindings are configured at the `iot.box` level and don’t automatically follow new records.
* Any reorganization would require manual reassignment or frontend reloads, which degrade user experience during live operations.
* Maintaining dynamic rebindings adds risk of race conditions and state desynchronization between PoS clients and IoT boxes.

Given these findings, the most stable and predictable configuration pattern is to **assign static IP addresses or static DHCP reservations** to all IoT boxes. This ensures that:

* The FQDN (`<tenant>.odoo-iot.com`) remains constant.
* The corresponding `iot.box` record remains consistent in Odoo.
* Cashiers and PoS users experience uninterrupted connectivity with their configured IoT hardware.

From a maintainability standpoint, static addressing eliminates the need for custom controller overrides, reduces side effects in the `/iot/setup` synchronization process, and simplifies network troubleshooting.

---

## 9. Conclusions

1. **HTTPS/WSS traffic between PoS and IoT remains entirely within the local network.**
   Once the FQDN resolves, the connection never requires WAN access; the reverse proxy loops requests to localhost.

2. **Odoo’s public DNS intentionally serves private IP A-records**, which is why Google DNS must be used for consistent resolution.

3. **TLS integrity is preserved** by Odoo’s wildcard certificate strategy, allowing a single certificate to authenticate all IoT subdomains securely.

4. **WAN connectivity is required only for:**

   * Initial registration and pairing
   * Certificate renewal via Let’s Encrypt
   * DNS bootstrap via Google DNS

5. **Offline operation is fully achievable** by caching or locally pinning the FQDN→IP mapping through hosts overrides or a persistent DNS cache.

---

## 10. References

* [IoT General Information — Odoo 19 Documentation](https://www.odoo.com/documentation/19.0/applications/general/iot.html)
* [HTTPS certificate (IoT) -- Odoo 19.0 documentation](https://www.odoo.com/documentation/19.0/applications/general/iot/iot_advanced/https_certificate_iot.html#the-iot-system-s-homepage-can-be-accessed-using-its-ip-address-but-not-the-xxx-odoo-iot-com-url)
* [IoT system connection to Odoo — Odoo 19 documentation](https://www.odoo.com/documentation/19.0/applications/general/iot/connect.html)
* [Let’s Encrypt — ACME Protocol Specification](https://letsencrypt.org/docs/client-options/)
* [Google Public DNS — RFC 1918 Resolution Behavior](https://developers.google.com/speed/public-dns/docs/using)

---

*Prepared as part of internal research on Odoo IoT deployment architecture, communication topology, and offline operation feasibility for Windows Virtual IoT environments.*