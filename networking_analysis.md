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
| [4.9 Odoo's Local Network Access option](#49-odoos-local-network-access-option) | Why Odoo added the HTTP option and how it relates to the certificate |
| [4.10 LAN reachability and caller access](#410-lan-reachability-and-caller-access) | Which network controls keep IoT routes off the public Internet |
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

An eligible production Odoo IoT installation can receive a **wildcard TLS certificate** issued by **Let’s Encrypt**, provisioned and renewed by Odoo’s cloud service. Staging and development databases may not qualify.

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

The diagram shows the certificate-backed HTTPS mode. Section 4.9 describes
Odoo's later HTTP option.

```
+---------------------+           +---------------------------+
| Browser (PoS Front) |  HTTPS/WSS| Odoo Cloud (SaaS/SH)     |
|---------------------|<----------|---------------------------|
|   Loads PoS client  |           | Serves PoS application    |
|   JS constructs URL |           | Provides certificate API  |
+----------^----------+           +-------------v-------------+
           |                                     
           | HTTPS/WSS (LAN or NAT loopback)
           |
+----------+--------------------------------------+
| Local IoT Device (Windows Virtual IoT)          |
|------------------------------------------------|
| Reverse Proxy (nginx, port 443)                |
| - Serves wildcard cert from Odoo               |
| - Terminates TLS                               |
| - Proxies HTTP to localhost:8069 (Odoo IoT)   |
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

The IoT runtime calls Odoo's endpoint
`https://www.odoo.com/odoo-enterprise/iot/x509` with the database UUID and
enterprise code. If the request succeeds, the endpoint returns `x509_pem` and
`private_key_pem`. The IoT runtime writes those values to
`/etc/ssl/certs/nginx-cert.crt` and `/etc/ssl/private/nginx-cert.key` on Linux,
or to `nginx-cert.crt` and `nginx-cert.key` in the Windows Nginx configuration.
It then starts or restarts Nginx. See Odoo 18's
[`load_certificate()` implementation](https://github.com/odoo/odoo/blob/cc5c3a7cfaec03414773948a5ef3ace97ff64583/addons/hw_drivers/tools/helpers.py).
The observed certificate was issued by Let's Encrypt. This client-side source
does not establish how Odoo obtains that certificate or handles ACME challenges.

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

The browser-to-nginx connection uses TLS. nginx then forwards the decrypted request over HTTP to `127.0.0.1:8069`. TLS does not extend to that local hop.

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
* `load_certificate()` uses HTTPS but sets `cert_reqs='CERT_NONE'` for the request to Odoo. The client therefore does not validate the server certificate during provisioning. The source establishes that risk but does not quantify its likelihood or impact.
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

Static addressing reduces re-registration churn and simplifies troubleshooting. It does not extend a certificate's validity period.

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

### 4.9 Odoo's Local Network Access option

Odoo added `point_of_sale.use_lna` as an alternative to the certificate-backed HTTPS route for POS browser requests. Chrome's Local Network Access permission and Odoo's setting are different. Chrome controls whether a site can reach local addresses. Odoo's setting chooses how its browser code contacts the IoT host.

Odoo's [November 2025 POS commit](https://github.com/odoo/odoo/commit/0e9a75ddc11f87ba7f86e013821d4f06e871c0bf) states the reason: Chrome 142's Local Network Access support allows local HTTP requests from an HTTPS page without a mixed-content error. The commit says this removes the certificate requirement for Epson printers and the black box. The [February 2026 Odoo 18 backport](https://github.com/odoo/odoo/commit/cc5c3a7cfaec03414773948a5ef3ace97ff64583) extends the same option to POS IoT requests so an IoT box can work without an HTTPS certificate.

Those commit messages support a specific reading of the design: Odoo used `use_lna` as an opt-in, certificate-free HTTP mode and kept the existing HTTPS mode for hosts with working certificates. They do not say that Chrome requires HTTP for Local Network Access. The commits and linked pull request do not explain whether Odoo considered a separate setting for browser permission while retaining HTTPS.

For a POS page loaded over HTTPS, `point_of_sale.use_lna` selects one request path:

| Setting | Browser request | IoT certificate |
| --- | --- | --- |
| `false` | HTTPS to the saved `.odoo-iot.com` hostname | The browser validates it |
| `true` | HTTP to the local IP derived from that hostname, with `targetAddressSpace: "local"` | Not used for that request |

Both paths reach the same IoT application if the selected host port is reachable. Odoo does not send an action on both paths or fall back after a failed request. The certificate can remain installed when the POS selects HTTP, but it cannot protect that HTTP request. Browser permission also does not encrypt traffic, authenticate the IoT host, or restrict the host's listening ports. The network firewall and service bindings determine whether the unused HTTP path remains reachable.

Chrome's [Local Network Access rules](https://developer.chrome.com/blog/local-network-access) do not require HTTP. They gate requests from a public site to a local address regardless of whether the destination uses HTTP or HTTPS. The permission also provides a mixed-content exception for eligible HTTP requests from an HTTPS page. That exception helps devices without trusted certificates. An HTTPS request needs no mixed-content exception, although Chrome may still ask the user for local-network permission.

Odoo's [October 2025 Enterprise revert](https://github.com/odoo/enterprise/commit/c1b85364f98e5de42fc6b8b9b66327d10cf557cb) makes the distinction explicit. Its commit message says `targetAddressSpace: "local"` was needed for HTTP from an HTTPS page when a domain resolves to a local IP, but not for Odoo's HTTPS-to-HTTPS requests. The revert removed that fetch option from ordinary HTTPS IoT requests. It did not remove Chrome's local-network permission.

Odoo 18 couples its `use_lna` setting to an HTTP downgrade. In `formatEndpoint(...)`, a true value forces `http:` and replaces the certificate hostname with a literal local IP. `_rpcIoT(...)` then sets `targetAddressSpace: "local"`. This is Odoo's implementation choice, not a requirement of the LNA protocol. A deployment with a valid certificate can keep HTTPS by leaving `point_of_sale.use_lna` false and allowing Chrome's local-network permission if prompted. It still needs working DNS, a reachable HTTPS listener, and a certificate valid for the requested hostname. Switching to the literal IP would usually lose the hostname match unless the certificate also covers that IP.

The trade-off is real: when Odoo uses HTTP, TLS no longer protects the browser-to-IoT request against reading or alteration on the local network. Chrome's permission limits which web origins may initiate local requests from that browser. It does not add encryption or authorize other clients on the LAN. A missing or invalid IoT certificate explains why Odoo offered this alternative, but LNA itself does not force the downgrade.

The relevant Odoo 18 code is available at these commit-pinned revisions:

* [`point_of_sale/controllers/main.py` reads `point_of_sale.use_lna`](https://github.com/odoo/odoo/blob/cc5c3a7cfaec03414773948a5ef3ace97ff64583/addons/point_of_sale/controllers/main.py).
* [`point_of_sale/static/src/utils.js` selects HTTP and the local IP](https://github.com/odoo/odoo/blob/cc5c3a7cfaec03414773948a5ef3ace97ff64583/addons/point_of_sale/static/src/utils.js).
* [`point_of_sale/static/src/app/utils/init_lna.js` checks browser support and permission](https://github.com/odoo/odoo/blob/cc5c3a7cfaec03414773948a5ef3ace97ff64583/addons/point_of_sale/static/src/app/utils/init_lna.js).
* [`pos_iot/static/src/overrides/models/pos_store.js` calls `setLna(...)`](https://github.com/odoo/enterprise/blob/5ed62c6a700d33449ffe30fb3a78dc7cc6e3a0ed/pos_iot/static/src/overrides/models/pos_store.js).
* [`iot/static/src/iot_longpolling.js` builds the IoT URL and `fetch()` options](https://github.com/odoo/enterprise/blob/5ed62c6a700d33449ffe30fb3a78dc7cc6e3a0ed/iot/static/src/iot_longpolling.js).

These are source and commit-history findings, not a runtime test of either connection mode.

---

### 4.10 LAN reachability and caller access

Odoo's [Windows virtual IoT guide](https://www.odoo.com/documentation/18.0/applications/general/iot/windows_iot.html) and [IoT box guide](https://www.odoo.com/documentation/18.0/applications/general/iot/iot_box.html) both warn against public Internet exposure. The Windows guide describes firewall exceptions for TCP ports `8069`, `80`, and `443`, as needed for local access. It also tells operators to choose the applicable Windows Firewall profiles. Neither the HTTPS certificate nor `point_of_sale.use_lna` restricts the IP addresses that may reach an open port.

The operator's firewall and network routing must keep those ports off the public Internet. For a narrower LAN boundary, Windows Firewall can limit an inbound rule's remote addresses to the POS network or specific clients, separately from its network profile. A rule that allows the Private profile does not by itself specify which remote IP addresses may connect. See [Microsoft's firewall rule guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure).

This boundary matters for [`/hw_drivers/action` in Odoo 18](https://github.com/odoo/odoo/blob/cc5c3a7cfaec03414773948a5ef3ace97ff64583/addons/hw_drivers/controllers/driver.py#L25). Its route declares `auth='none'`, `cors='*'`, and `csrf=False`. The route identifies a device and handles action data, but does not authenticate the caller as an Odoo user. TLS authenticates the IoT server to the browser and protects that connection; it does not turn the route into a client-authenticated service. LAN isolation excludes public callers only when the actual firewall and network configuration enforce it. Other clients on the allowed LAN remain within the reachability boundary.

---

## 5. Behavior With and Without WAN Connectivity

| Scenario                    | DNS Resolution                                                       | Certificate Validity               | HTTPS/WSS Operation                                         |
| --------------------------- | -------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------- |
| **WAN Up**                  | Google DNS resolves hostnames normally                               | Valid (Let’s Encrypt)              | All traffic flows; requests remain local or hairpin via NAT |
| **WAN Down (short outage)** | Windows DNS cache or local caching resolver retains entries          | Still valid                        | HTTPS/WSS continues; PoS can function offline               |
| **WAN Down (long outage)**  | Cached entries expire → requires local fallback (e.g., hosts update) | Still valid until expiry           | HTTPS/WSS still local if hostname resolves                  |
| **Certificate Renewal**     | Requires WAN for Let’s Encrypt ACME                                  | Odoo handles renewal automatically | No action needed locally                                    |

Once the IoT host is paired and its certificate is installed, its HTTPS
connection with a local browser can stay on the LAN if the hostname resolves to
the private IP. Pairing, certificate renewal, and communication with the Odoo
database still need their respective network paths. This table covers the
certificate-backed mode, not `point_of_sale.use_lna` HTTP mode.

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
     This preserves hostname resolution during a WAN outage. It does not, by itself, prove that the full POS workflow works offline.

---

## 8. Summary of Key Findings

| Component                        | Function                                                | Managed By                 | Dependency                 |
| -------------------------------- | ------------------------------------------------------- | -------------------------- | -------------------------- |
| **Wildcard TLS certificate**     | Enables HTTPS/WSS trust for all IoT subdomains          | Odoo Cloud (Let’s Encrypt) | WAN only for renewal       |
| **Dynamic DNS (`odoo-iot.com`)** | Encodes private IP in hostname; resolves via Google DNS | Odoo Cloud                 | WAN for initial resolution |
| **Reverse proxy (port 443)**     | Terminates TLS and forwards to local IoT service        | Local IoT software         | LAN-only operation         |
| **IoT backend (port 8069)**      | Handles hardware drivers and API calls                  | Local IoT software         | LAN-only operation         |
| **Browser PoS client**           | Uses HTTPS by default, or local HTTP when `point_of_sale.use_lna` is enabled | User device | Depends on selected path |
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

2. **The IoT hostname must resolve to the box's LAN address** for local HTTPS access. Google Public DNS is one documented option; a correctly configured local resolver or host entry can provide the same mapping.

3. **TLS integrity is preserved** by Odoo’s wildcard certificate strategy, allowing a single certificate to authenticate all IoT subdomains securely.

4. **Some IoT operations still need WAN connectivity**, including:

   * Initial registration and pairing
   * Certificate renewal via Let’s Encrypt
   * DNS bootstrap via Google DNS

5. **Local hostname resolution can preserve the browser-to-IoT HTTPS link during a WAN outage.** It does not prove that the full POS workflow works offline.

6. **Odoo's Local Network Access option permits an HTTP alternative.** Odoo added it so POS browser requests can reach local hardware without an IoT HTTPS certificate. It does not make the certificate and browser permission interchangeable.

---

## 10. References

* [IoT General Information — Odoo 19 Documentation](https://www.odoo.com/documentation/19.0/applications/general/iot.html)
* [HTTPS certificate (IoT) -- Odoo 19.0 documentation](https://www.odoo.com/documentation/19.0/applications/general/iot/iot_advanced/https_certificate_iot.html#the-iot-system-s-homepage-can-be-accessed-using-its-ip-address-but-not-the-xxx-odoo-iot-com-url)
* [IoT system connection to Odoo — Odoo 19 documentation](https://www.odoo.com/documentation/19.0/applications/general/iot/connect.html)
* [Let’s Encrypt — ACME Protocol Specification](https://letsencrypt.org/docs/client-options/)
* [Google Public DNS — RFC 1918 Resolution Behavior](https://developers.google.com/speed/public-dns/docs/using)
* [Odoo POS Local Network Access introduction](https://github.com/odoo/odoo/commit/0e9a75ddc11f87ba7f86e013821d4f06e871c0bf)
* [Odoo 18 IoT Local Network Access backport](https://github.com/odoo/odoo/commit/cc5c3a7cfaec03414773948a5ef3ace97ff64583)
* [Odoo Enterprise HTTPS request annotation revert](https://github.com/odoo/enterprise/commit/c1b85364f98e5de42fc6b8b9b66327d10cf557cb)
* [Chrome Local Network Access explanation](https://developer.chrome.com/blog/local-network-access)
* [Odoo 18 Windows virtual IoT setup and firewall guidance](https://www.odoo.com/documentation/18.0/applications/general/iot/windows_iot.html)
* [Odoo 18 IoT box network guidance](https://www.odoo.com/documentation/18.0/applications/general/iot/iot_box.html)
* [Microsoft Windows Firewall rule scope](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure)

---

*Prepared as part of internal research on Odoo IoT deployment architecture, communication topology, and offline operation feasibility for Windows Virtual IoT environments.*
