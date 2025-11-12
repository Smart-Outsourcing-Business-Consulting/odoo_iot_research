# IPv4 Detection Scripts — Cross-Platform Overview

---

## Table of Contents

* [Purpose and Context](#purpose-and-context)
* [PowerShell Script Explained](#powershell-script-explained)

  * [1. Retrieve All Default Routes](#1-retrieve-all-default-routes)
  * [2. Compute Effective Routing Cost](#2-compute-effective-routing-cost)
  * [3. Query the Interface’s IPv4 Addresses](#3-query-the-interfaces-ipv4-addresses)
  * [4. Output](#4-output)
* [Summary Insight](#summary-insight)
* [Bash Script Explained](#bash-script-explained)

  * [1. Execution Posture](#1-execution-posture)
  * [2. Policy Toggles (Enterprise Guardrails)](#2-policy-toggles-enterprise-guardrails)
  * [3. Helper Primitives (iproute2--awk)](#3-helper-primitives-iproute2--awk)

    * [`is_rfc1918()`](#is_rfc1918)
    * [`ipv4_on_dev(dev)`](#ipv4_on_devdev)
    * [`best_default_dev()`](#best_default_dev)
    * [`best_connected_dev()`](#best_connected_dev)
    * [`first_suitable_dev()`](#first_suitable_dev)
  * [4. Selection Pipeline (Control Flow)](#4-selection-pipeline-control-flow)

    * [Step 1 — Default-Route Winner](#step-1--default-route-winner)
    * [Step 2 — Connected-Route Winner (Offline Path)](#step-2--connected-route-winner-offline-path)
    * [Step 3 — Any UP Device (Last Resort)](#step-3--any-up-device-last-resort)
    * [Step 4 — Address Extraction & Prioritization](#step-4--address-extraction--prioritization)
  * [5. Error Handling and Exit Codes](#5-error-handling-and-exit-codes)
  * [6. Enterprise-Grade Design Attributes](#6-enterprise-grade-design-attributes)
  * [7. Operational Knobs](#7-operational-knobs)
  * [8. Typical Failure Modes Neutralized](#8-typical-failure-modes-neutralized)
* [Result](#result)

---

## Purpose and Context

The scripts (one for **Windows** using PowerShell, one for **Linux** using Bash) in this folder form part of a cross-platform effort to reliably determine a machine’s **active IPv4 address** — specifically the one the operating system would use for outbound communication.

The end goal is to use that IP address together with the SAN/subject discussed in [networking_analysis.md](../networking_analysis.md) in the OS hosts file, in order to have a DNS record that always resolves. Remember that the TLS handshake in an HTTPS/WSS connection is the only thing that needs to be resolved.

The goal is to achieve **deterministic and environment-aware IP detection**, independent of external connectivity, to support IoT and point-of-sale (PoS) deployments where Odoo’s IoT services need to self-identify correctly on LANs or during WAN outages.

By contrast, **Odoo’s built-in helper**:

```python
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        return s.getsockname()[0]
    finally:
        s.close()
```

uses a lightweight trick — it “connects” a UDP socket to Google DNS (`8.8.8.8`) and asks the OS which interface that would egress through.
This works on simple networks but can misreport the IP under VPNs, captive portals, or when there’s no default route.
Your PowerShell and Bash counterparts explicitly query the routing table and interface metrics, so they always reflect the OS’s real routing decisions — even offline.

---

## PowerShell Script Explained

```powershell
$ErrorActionPreference = 'Stop'
```

* Enforces **fail-fast behavior**: any error halts execution instead of being silently ignored.

### 1. Retrieve All Default Routes

```powershell
$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0
```

* Queries the Windows routing table for **default routes** (`0.0.0.0/0`).
* Multiple default routes may exist if there are several NICs or VPNs active.

### 2. Compute Effective Routing Cost

```powershell
$best = $routes |
  Sort-Object {
    $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric
  }, RouteMetric |
  Select-Object -First 1
```

* Windows uses two metrics for route selection:

  * **RouteMetric** – specific to the route entry.
  * **InterfaceMetric** – specific to the NIC.
* The sum represents the **effective cost**.
* This block sorts all default routes by that combined cost and picks the **lowest total**, i.e., the interface the OS would truly use for outbound traffic.

### 3. Query the Interface’s IPv4 Addresses

```powershell
$ipv4 = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $best.ifIndex |
  Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.AddressState -eq 'Preferred' } |
  Select-Object -First 1 -ExpandProperty IPAddress
```

* Fetches all IPv4 addresses assigned to the chosen interface.
* Filters to exclude:

  * **APIPA (169.254.x.x)** — self-assigned, non-routable addresses.
  * Any address not in **Preferred** state (avoiding deprecated or transient ones).
* Selects the first valid, preferred IPv4 and outputs it.

### 4. Output

```powershell
$ipv4
```

* The resulting string is the **primary operational IPv4 address** of the system — the same address Windows would use for outbound packets via its best route.

---

## Bash Script Explained

### 1. Execution Posture

* `set -euo pipefail`
  Raises the bar on robustness: bail on any error (`-e`), undefined vars (`-u`), and pipeline failures (`-o pipefail`). This prevents “mysteriously blank IP” scenarios from leaking downstream.

---

### 2. Policy Toggles (Enterprise Guardrails)

* `PREFER_RFC1918` (default `1`) – Biases selection toward private IPv4 space (10/8, 172.16/12, 192.168/16).
* `DENY_IF_REGEX` – Default denylist for noisy/ephemeral adapters (loopback, Docker, veths, tunnels, VPNs, etc.).
* `ALLOW_IF_REGEX` – Optional allowlist for strict interface control.

These are environment-overridable so Ops can tune behavior without editing code.

---

### 3. Helper Primitives (Pure iproute2 + awk)

#### `is_rfc1918()`

* Simple pattern test to classify private IPv4s (`10.*`, `192.168.*`, and `172.16–31.*`).

#### `ipv4_on_dev(dev)`

* Returns the first **global, non-link-local, non-deprecated** IPv4 on a device via:

  * `ip -4 -o addr show dev <dev> scope global`
  * Excludes `169.254.*` and `deprecated` addresses.

#### `best_default_dev()`

* Finds the device carrying the **default route** with the **lowest metric**:

  * Example: `default via 10.0.0.1 dev ens160 metric 5`
* Mirrors the Windows “effective metric” concept.

#### `best_connected_dev()`

* Fallback using **on-link kernel routes** when there’s **no default route**:

  * `ip -4 route show table main scope link proto kernel`
* Guarantees a LAN identity during WAN outages.

#### `first_suitable_dev()`

* Validates candidate interfaces by:

  1. Filtering out denied or downed interfaces.
  2. Ensuring link state is UP or LOWER_UP.
  3. Returning the first viable match.

---

### 4. Selection Pipeline (Control Flow)

#### Step 1 — Default-Route Winner

* `default_dev="$(best_default_dev || true)"`
* Filters through policy gates to select the cleanest primary interface.

#### Step 2 — Connected-Route Winner (Offline Path)

* If no default device, fallback to `best_connected_dev`.
* Ensures LAN IP selection even if WAN is blocked.

#### Step 3 — Any UP Device (Last Resort)

* Enumerates UP interfaces with valid global IPv4s.
* Ensures forward progress on heavily customized systems.

#### Step 4 — Address Extraction & Prioritization

* Collects all valid IPv4s for the chosen device.
* Prioritizes RFC1918 if configured.
* Outputs the chosen IPv4 to stdout.

---

### 5. Error Handling and Exit Codes

* No valid device → `exit 2`
* Device found but no usable IPv4 → `exit 3`
  Distinct exit codes simplify orchestration in tools like **systemd**, **Ansible**, or custom agents.

---

### 6. Enterprise-Grade Design Attributes

* **Deterministic intent** — Mirrors kernel routing logic.
* **Topology hygiene** — Ignores tunnels, Docker bridges, and VPNs unless allowed.
* **Offline-safe** — Never requires actual traffic.
* **Configurable** — All behavior tunable via environment variables.
* **Minimal dependencies** — Works with stock `iproute2` and `awk`.

---

### 7. Operational Knobs

* Prefer a specific fabric:
  `ALLOW_IF_REGEX='^ens160|^eth0'`
* Allow overlays (e.g., Tailscale):
  Remove from `DENY_IF_REGEX`.
* Add IPv6 observability:
  Clone logic with `ip -6`.

---

### 8. Typical Failure Modes Neutralized

* VPN force-tunnels stealing identity.
* No default route during maintenance windows.
* DHCP flaps or deprecated address states.

---

**Result:**
A predictable, policy-driven primitive that outputs the **business-correct IPv4** across complex, multi-NIC topologies — ready for integration into automated naming, TLS, and IoT-identity workflows.

---

## Summary Insight

| Script                       | Platform                | Logic Source                      | Strength                             |
| ---------------------------- | ----------------------- | --------------------------------- | ------------------------------------ |
| **get_ip()**                 | Cross-platform (Python) | Socket to `8.8.8.8`               | Simple, but assumes WAN reachability |
| **PowerShell IPv4 resolver** | Windows                 | Routing table + interface metrics | Deterministic, offline-safe          |
| **Bash IPv4 resolver**       | Linux                   | `iproute2` + metrics              | Deterministic, offline-safe          |

Together, these scripts create a **platform-consistent, policy-aware IP discovery layer** for IoT or PoS nodes where IP stability drives identity, hostname generation, and trust mapping — closing the reliability gap left by Odoo’s default socket method.

---
