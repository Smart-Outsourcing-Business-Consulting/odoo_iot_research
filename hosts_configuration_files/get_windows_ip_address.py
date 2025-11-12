import os
import re
import subprocess
import shutil
import tempfile

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
MARK_BEGIN = "# >>> IOT_HOSTMAP BEGIN"
MARK_END   = "# <<< IOT_HOSTMAP END"


def get_primary_ipv4_via_powershell() -> str:
    """
    Use Windows routing logic to determine the true primary IPv4:
    1. Get all default (0.0.0.0/0) routes.
    2. Compute the effective metric = RouteMetric + InterfaceMetric.
    3. Pick the NIC with the lowest metric.
    4. Return the first Preferred, non-APIPA IPv4 on that NIC.
    """
    ps = r'''
$ErrorActionPreference = 'Stop'

# Pick the default route with the lowest *effective* metric (route + interface)
$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0
$best = $routes |
  Sort-Object {
    $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric
  }, RouteMetric |
  Select-Object -First 1

# Lift the “best” NIC’s primary, usable IPv4 (no APIPA, preferred state)
$ipv4 = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $best.ifIndex |
  Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.AddressState -eq 'Preferred' } |
  Select-Object -First 1 -ExpandProperty IPAddress

$ipv4
'''
    out = subprocess.check_output(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        text=True,
        encoding="utf-8",
        errors="ignore",
    ).strip()

    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", out):
        raise RuntimeError(f"Unexpected IPv4 output from PowerShell: {out!r}")
    return out


def read_wildcard_suffix_from_odoo_conf(conf_path: str) -> str:
    """Read 'iot_wildcard_suffix = d73e7513.odoo-iot.com' from odoo.conf."""
    with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"\s*iot_wildcard_suffix\s*=\s*([A-Za-z0-9\.\-]+)\s*$", line)
            if m:
                return m.group(1).strip()
    raise RuntimeError(f"iot_wildcard_suffix not found in {conf_path}")


def build_iot_fqdn_from_local_ip(wildcard_suffix: str, ip: str) -> str:
    """Convert 192.168.1.143 + suffix → 192-168-1-143.d73e7513.odoo-iot.com"""
    return f"{ip.replace('.', '-')}.{wildcard_suffix.strip('.')}"


def update_hosts_file(fqdn: str, ip: str):
    """Safely update Windows hosts to bind FQDN→IP."""
    bak = HOSTS_PATH + ".bak_iot"
    shutil.copyfile(HOSTS_PATH, bak)

    with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    pattern = re.escape(MARK_BEGIN) + r".*?" + re.escape(MARK_END) + r"\n?"
    content = re.sub(pattern, "", content, flags=re.DOTALL)

    block = f"{MARK_BEGIN}\n{ip} {fqdn}\n{MARK_END}\n"
    content = content.rstrip() + "\n\n" + block

    fd, tmp = tempfile.mkstemp(prefix="hosts_", suffix=".tmp")
    os.close(fd)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, HOSTS_PATH)

    subprocess.run(["ipconfig", "/flushdns"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[INFO] hosts updated: {fqdn} → {ip}")


def main():
    conf_path = os.environ.get("ODOO_CONF_PATH", r"C:\odoo\odoo.conf")
    ip = get_primary_ipv4_via_powershell()

    print(f"[INFO] IoT IPv4 Address: {ip}")
if __name__ == "__main__":
    main()

