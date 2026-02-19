import logging
import os
import time
import requests
import ipaddress
import urllib3
from collections import defaultdict
from functools import lru_cache

# Environment variables
OPNSENSE_URL = os.getenv("OPNSENSE_URL") or None
OPNSENSE_API_KEY = os.getenv("OPNSENSE_API_KEY") or None
OPNSENSE_API_SECRET = os.getenv("OPNSENSE_API_SECRET") or None
TECHNITIUM_URL = os.getenv("TECHNITIUM_URL") or None
TECHNITIUM_TOKEN = os.getenv("TECHNITIUM_TOKEN") or None
DNS_ZONE_SUBNETS = os.getenv("DNS_ZONE_SUBNETS") or None
DO_V4 = ((os.getenv("DO_V4") or "false").lower() == "true")
IGNORE_LINK_LOCAL = ((os.getenv("IGNORE_LINK_LOCAL") or "true").lower() == "true")
VERIFY_HTTPS = ((os.getenv("VERIFY_HTTPS") or "true").lower() == "true")
CLOCK = int(os.getenv("CLOCK") or "30")
# How often to refresh all records (in cycles)
REFRESH_CYCLE = int(os.getenv("REFRESH_CYCLE") or "1440")

# Technitium settings for auto-created reverse zones
TECHNITIUM_PTR_CATALOG = os.getenv("TECHNITIUM_PTR_CATALOG") or "cluster-catalog.dns.local"
TECHNITIUM_USE_SOA_SERIAL_DATE_SCHEME = ((os.getenv("TECHNITIUM_USE_SOA_SERIAL_DATE_SCHEME") or "true").lower() == "true")
# IPv6 reverse zone prefix length to create (must be nibble-aligned). Default /64.
TECHNITIUM_IPV6_PTR_PREFIXLEN = int(os.getenv("TECHNITIUM_IPV6_PTR_PREFIXLEN") or "64")
# If catalog assignment fails (missing permissions), retry creating zone without catalog.
TECHNITIUM_ZONE_CREATE_FALLBACK_NO_CATALOG = ((os.getenv("TECHNITIUM_ZONE_CREATE_FALLBACK_NO_CATALOG") or "true").lower() == "true")
# If a PTR-only record exists but points somewhere else, replace it (delete+add).
TECHNITIUM_PTR_ONLY_OVERWRITE = ((os.getenv("TECHNITIUM_PTR_ONLY_OVERWRITE") or "false").lower() == "true")

# WireGuard support
# Format: "wg_instance_name=dns.zone,another_instance=other.zone"
WG_INSTANCES_DNSZONES = os.getenv("WG_INSTANCES_DNSZONES") or None
ENABLE_WIREGUARD_DNS = ((os.getenv("ENABLE_WIREGUARD_DNS") or "false").lower() == "true")

def get_opnsense_data(path):
    r = requests.get(url=OPNSENSE_URL + path, verify=VERIFY_HTTPS, auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET))
    if r.status_code != 200:
        logging.error("Error occurred" + str(r.status_code) + ": " + r.text)
        return None
    return r.json()

def get_ndp():
    return get_opnsense_data("/api/diagnostics/interface/search_ndp")

def get_dhcp4_leases():
    return get_opnsense_data("/api/dhcpv4/leases/searchLease")

def get_dhcp4_leases_v2():
    data = get_opnsense_data("/api/dnsmasq/leases/search")
    if not isinstance(data, dict):
        return data

    rows = data.get("rows")
    if not isinstance(rows, list):
        return data

    # Build a list of allowed IPv4 networks from DNS_ZONE_SUBNETS.
    # Format: "192.168.1.0/24=zone.example,192.168.2.0/24=...".
    # Users may escape '=' in env files; we support both '=' and '\='.
    allowed_nets: list[ipaddress.IPv4Network] = []
    if DNS_ZONE_SUBNETS:
        for part in DNS_ZONE_SUBNETS.split(","):
            part = part.strip()
            if not part:
                continue

            # normalize possible escaped '='
            part_norm = part.replace("\\=", "=")
            subnet = part_norm.split("=", 1)[0].strip()
            try:
                net = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                logging.warning(f"Invalid subnet in DNS_ZONE_SUBNETS ignored: {subnet}")
                continue

            if isinstance(net, ipaddress.IPv4Network):
                allowed_nets.append(net)

    # Filter out IPv6 entries and IPv4 entries not in DNS_ZONE_SUBNETS.
    v4_rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        addr = row.get("address")
        if not isinstance(addr, str):
            continue
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue

        if ip.version != 4:
            continue

        if allowed_nets and not any(ip in net for net in allowed_nets):
            continue

        v4_rows.append(row)

    data["rows"] = v4_rows

    # Keep counters consistent if present
    if "rowCount" in data:
        data["rowCount"] = len(v4_rows)
    if "total" in data:
        data["total"] = len(v4_rows)

    return data

def get_wireguard_servers():
    """Retrieve WireGuard server configurations from OPNsense."""
    return get_opnsense_data("/api/wireguard/server/search_server")

def get_wireguard_clients():
    """Retrieve WireGuard client configurations from OPNsense."""
    return get_opnsense_data("/api/wireguard/client/search_client")

def build_matches(ndp, leases):
    matches = set()
    hostname_to_macs = defaultdict(lambda: defaultdict(list))

    for e in leases["rows"]:
        ip6s = tuple(
            x["ip"].split("%")[0] for x in ndp["rows"]
            if x["mac"] == e["hwaddr"] and x["intf_description"] == e["if_descr"]
        )
        if IGNORE_LINK_LOCAL:
            ip6s = tuple(ip for ip in ip6s if not ipaddress.ip_address(ip).is_link_local)
        if len(ip6s) == 0 and not DO_V4:
            continue

        hostname = e["hostname"]
        if hostname == "*": hostname = ""
        if hostname:
            hostname_to_macs[hostname][e["if_descr"]].append(e["hwaddr"])

        matches.add((e["address"], ip6s, hostname, e["if_descr"], e["hwaddr"]))

    # Handle duplicate hostnames on the same interface
    adjusted_matches = set()
    for match in matches:
        ip4, ip6s, hostname, if_descr, mac = match
        if hostname and len(hostname_to_macs[hostname][if_descr]) > 1:
            # Add the last 4 characters of the MAC address to the hostname
            hostname = f"{hostname}-{mac.replace(':', '')[-4:]}"
        adjusted_matches.add((ip4, ip6s, hostname))

    return adjusted_matches

def find_zone(zones, ip4):
    for zone in zones:
        if ip4 in zone[0]: return zone[1]
    return None

def technitium_get(path: str, params: dict | None = None):
    """Small helper to call Technitium HTTP API."""
    url = f"{TECHNITIUM_URL}{path}"
    params = dict(params or {})
    params.setdefault("token", TECHNITIUM_TOKEN)
    return requests.get(url=url, params=params, verify=VERIFY_HTTPS)


def technitium_request(path: str, params: dict | None = None, *, action: str = "Technitium request") -> tuple[bool, dict]:
    """Call Technitium API and validate both HTTP and JSON status.

    Returns: (ok, payload)
    - ok is True only when HTTP is 200 AND JSON has {"status":"ok"}
    - payload is {} on parse failures
    """
    r = technitium_get(path, params=params)

    # Technitium often responds with HTTP 200 even on errors; still handle non-200.
    if r.status_code != 200:
        logging.error(f"{action} failed (HTTP {r.status_code}): {r.text}")
        return False, {}

    try:
        payload = r.json() or {}
    except Exception:
        logging.error(f"{action} failed (invalid JSON): {r.text}")
        return False, {}

    if payload.get("status") == "ok":
        return True, payload

    msg = payload.get("errorMessage") or payload.get("message") or str(payload)
    logging.error(f"{action} failed (status={payload.get('status')}): {msg}")
    return False, payload


def technitium_list_zones() -> list[str]:
    """Return a list of zone domain names available on Technitium."""
    ok, payload = technitium_request("/api/zones/list", action="List zones")
    if not ok:
        return []

    data = payload.get("response", {})

    zones: list[str] = []
    # Technitium's response shape can vary slightly by version; try a few known keys.
    for key in ("zones", "zoneList"):
        if isinstance(data.get(key), list):
            for z in data[key]:
                if isinstance(z, str):
                    zones.append(z)
                elif isinstance(z, dict) and isinstance(z.get("name"), str):
                    zones.append(z["name"])

    # Fallback: if response includes an array directly
    if not zones and isinstance(data, list):
        for z in data:
            if isinstance(z, str):
                zones.append(z)
            elif isinstance(z, dict) and isinstance(z.get("name"), str):
                zones.append(z["name"])

    return sorted(set(zones))


@lru_cache(maxsize=1)
def technitium_zone_set() -> set[str]:
    return set(technitium_list_zones())


def refresh_technitium_zone_cache():
    technitium_zone_set.cache_clear()


def reverse_zone_name_for_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Compute the reverse zone name for an IP address.

    For IPv4 we use /24 reverse zone (x.y.z.in-addr.arpa).

    For IPv6 we use a nibble-aligned reverse zone (ip6.arpa) based on
    TECHNITIUM_IPV6_PTR_PREFIXLEN (default /64).

    Note: ip6.arpa delegation is on 4-bit (nibble) boundaries, so prefix length
    must be a multiple of 4.
    """
    if ip.version == 4:
        # /24
        octets = str(ip).split(".")
        return ".".join(reversed(octets[:3])) + ".in-addr.arpa"

    # IPv6: nibble-aligned reverse zone
    prefixlen = TECHNITIUM_IPV6_PTR_PREFIXLEN
    if prefixlen % 4 != 0 or not (4 <= prefixlen <= 124):
        logging.warning(
            f"Invalid TECHNITIUM_IPV6_PTR_PREFIXLEN={prefixlen}; "
            "must be 4..124 and divisible by 4. Falling back to 64."
        )
        prefixlen = 64

    hex32 = ip.exploded.replace(":", "")
    nibbles = prefixlen // 4
    prefix_nibbles = hex32[:nibbles]
    return ".".join(reversed(prefix_nibbles)) + ".ip6.arpa"


def reverse_record_name_for_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return the full owner name for a PTR record for a single IP.

    Examples:
    - IPv4: 10.0.168.192.in-addr.arpa
    - IPv6: 0.3.6.7.1.0.8.b.8.a.e.e.7.6.4.3.0.0.b.d.7.6.3.3.7.b.3.b.0.2.6.0.0.a.2.ip6.arpa
    """
    if ip.version == 4:
        octets = str(ip).split(".")
        return ".".join(reversed(octets)) + ".in-addr.arpa"

    hex32 = ip.exploded.replace(":", "")
    return ".".join(reversed(hex32)) + ".ip6.arpa"


def technitium_create_zone(zone: str, zone_type: str = "Primary") -> bool:
    base_params = {
        "zone": zone,
        "type": zone_type,
        "useSoaSerialDateScheme": "true" if TECHNITIUM_USE_SOA_SERIAL_DATE_SCHEME else "false",
    }

    # First try: with catalog (if configured)
    params = dict(base_params)
    if TECHNITIUM_PTR_CATALOG:
        params["catalog"] = TECHNITIUM_PTR_CATALOG

    ok, payload = technitium_request("/api/zones/create", params=params, action=f"Create zone '{zone}'")

    # Fallback: retry without catalog on permission errors
    if (not ok) and TECHNITIUM_ZONE_CREATE_FALLBACK_NO_CATALOG and TECHNITIUM_PTR_CATALOG:
        err = (payload.get("errorMessage") or "").lower()
        if "access was denied" in err and "catalog" in err:
            logging.warning(
                f"Create zone '{zone}' failed due to catalog permissions; retrying without catalog..."
            )
            ok, payload = technitium_request(
                "/api/zones/create",
                params=base_params,
                action=f"Create zone '{zone}' (no catalog)",
            )

    if not ok:
        return False

    domain_created = (payload.get("response", {}) or {}).get("domain")
    logging.info(f"Created Technitium zone: {domain_created or zone}")
    refresh_technitium_zone_cache()
    return True


def ensure_reverse_zone_for_ip(ip_str: str) -> bool:
    """Ensure reverse zone exists for provided IP (especially needed for ptr=true record creation)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        logging.warning(f"Invalid IP for reverse zone check: {ip_str}")
        return False

    zone_name = reverse_zone_name_for_ip(ip)
    zones = technitium_zone_set()

    if zone_name in zones:
        return True

    logging.warning(f"Missing reverse zone '{zone_name}' for IP {ip_str}; creating it...")
    return technitium_create_zone(zone_name, zone_type="Primary")


def get_existing_records(domain, zone):
    ok, payload = technitium_request(
        "/api/zones/records/get",
        params={
            "domain": f"{domain}.{zone}",
            "zone": zone
        },
        action=f"Get records for {domain}.{zone}",
    )
    if not ok:
        return []
    return (payload.get("response", {}) or {}).get("records", [])


def delete_record(zone, domain, record_type, value):
    ok, _payload = technitium_request(
        "/api/zones/records/delete",
        params={
            "domain": f"{domain}.{zone}",
            "zone": zone,
            "type": record_type,
            "ipAddress": value,  # Use ipAddress instead of value for A/AAAA records
        },
        action=f"Delete {record_type} {domain}.{zone} => {value}",
    )
    if not ok:
        return
    logging.info(f"Deleted {record_type} record for {value} in {domain}.{zone}")


def add_record(zone, domain, record_type, ip):
    # ptr=true will fail if the corresponding reverse zone does not exist; ensure it proactively.
    ensure_reverse_zone_for_ip(ip)

    ok, _payload = technitium_request(
        "/api/zones/records/add",
        params={
            "domain": f"{domain}.{zone}",
            "zone": zone,
            "type": record_type,
            "ttl": 5,
            "expiryTtl": 604800,
            "overwrite": "false",
            "ptr": "false",
            "comments": "slaacsense",
            "ipAddress": ip,
        },
        action=f"Add {record_type} {domain}.{zone} => {ip}",
    )
    if not ok:
        return
    logging.info(f"Added {record_type} record for {ip} in {domain}.{zone}")


def reverse_record_owner_within_zone(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[str, str]:
    """Return (owner_fqdn, reverse_zone).

    reverse_zone is calculated using reverse_zone_name_for_ip() (/24 for v4, configurable nibble-prefix for v6).
    owner_fqdn is the full owner name inside that zone.

    For IPv6 this ensures we place PTRs in the configured reverse zone (e.g. /64), not a /128-only owner.
    """
    reverse_zone = reverse_zone_name_for_ip(ip)

    if ip.version == 4:
        # /24 zone: a.b.c.in-addr.arpa -> owner is last octet
        last_octet = str(ip).split(".")[3]
        owner = last_octet
        return f"{owner}.{reverse_zone}", reverse_zone

    # IPv6: reverse_zone is nibble-aligned (e.g. 16 nibbles for /64)
    prefixlen = TECHNITIUM_IPV6_PTR_PREFIXLEN
    if prefixlen % 4 != 0 or not (4 <= prefixlen <= 124):
        prefixlen = 64

    nibbles_in_zone = prefixlen // 4
    full_hex = ip.exploded.replace(":", "")  # 32 nibbles

    # owner labels are the remaining nibbles (from host part) in reverse order
    remainder = full_hex[nibbles_in_zone:]
    owner_labels = ".".join(reversed(remainder)) if remainder else ""

    owner_fqdn = f"{owner_labels}.{reverse_zone}" if owner_labels else reverse_zone
    return owner_fqdn, reverse_zone


def add_ptr_only(zone: str, domain: str, ip: str):
    """Create only a PTR for the given IP without publishing a forward AAAA record."""
    if not domain:
        return

    ensure_reverse_zone_for_ip(ip)

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        logging.warning(f"Skipping PTR-only for invalid IP: {ip}")
        return

    ptr_owner, ptr_zone = reverse_record_owner_within_zone(ip_obj)
    desired_ptr_name = f"{domain}.{zone}".lower().rstrip(".")

    # Extract hostname part from FQDN (ptr_owner is FQDN like "1.2.3.ip6.arpa", ptr_zone is "ip6.arpa")
    # We need just the label part before the zone
    if ptr_owner.endswith(f".{ptr_zone}"):
        ptr_label = ptr_owner[: -(len(ptr_zone) + 1)]  # Remove ".{ptr_zone}"
    else:
        ptr_label = ptr_owner  # Fallback if something went wrong

    # Dedup/overwrite protection: check if PTR already exists at ptr_owner
    existing_owner_records = get_existing_records(ptr_label, ptr_zone)
    existing_ptrs = [r for r in existing_owner_records if r.get("type") == "PTR"]

    for r in existing_ptrs:
        rdata = r.get("rData", {}) or {}
        # Technitium uses 'ptrName' for PTR RDATA
        current_ptr_name = str(rdata.get("ptrName") or "").lower().rstrip(".")

        if current_ptr_name == desired_ptr_name:
            # Already correct
            return

        if TECHNITIUM_PTR_ONLY_OVERWRITE and current_ptr_name:
            # Replace wrong target - need to use ptrName parameter for PTR delete
            ok, _payload = technitium_request(
                "/api/zones/records/delete",
                params={
                    "domain": ptr_owner,
                    "zone": ptr_zone,
                    "type": "PTR",
                    "ptrName": current_ptr_name,
                },
                action=f"Delete PTR {ptr_owner} => {current_ptr_name}",
            )
            if ok:
                logging.info(f"Deleted PTR record for {ptr_owner} -> {current_ptr_name}")
            break

    ok, _payload = technitium_request(
        "/api/zones/records/add",
        params={
            "domain": ptr_owner,
            "zone": ptr_zone,
            "type": "PTR",
            "ttl": 5,
            "expiryTtl": 604800,
            "overwrite": "true",  # Use overwrite=true to handle cases where record already exists
            "ptr": "false",
            "comments": "slaacsense",
            "ptrName": desired_ptr_name,
        },
        action=f"Add PTR-only {ip} => {desired_ptr_name}",
    )
    if not ok:
        return
    logging.info(f"Added PTR-only record for {ip} -> {desired_ptr_name}")


def parse_wg_instances_zones():
    """Parse WG_INSTANCES_DNSZONES env var into a dict mapping instance UUID to DNS zone.

    Format: "instance_name=dns.zone,another_instance=other.zone"
    Returns: dict with instance_name -> zone
    """
    if not WG_INSTANCES_DNSZONES:
        return {}

    mapping = {}
    for part in WG_INSTANCES_DNSZONES.split(","):
        part = part.strip()
        if not part:
            continue

        parts = part.split("=", 1)
        if len(parts) != 2:
            logging.warning(f"Invalid WG_INSTANCES_DNSZONES entry: {part}")
            continue

        instance_name, zone = parts[0].strip(), parts[1].strip()
        mapping[instance_name] = zone

    return mapping

def process_wireguard_clients():
    """Process WireGuard clients and create DNS records for them."""
    if not ENABLE_WIREGUARD_DNS or not WG_INSTANCES_DNSZONES:
        return set()

    wg_servers = get_wireguard_servers()
    if not wg_servers or not isinstance(wg_servers.get("rows"), list):
        logging.warning("Failed to retrieve WireGuard servers or invalid response")
        return set()

    wg_clients = get_wireguard_clients()
    if not wg_clients or not isinstance(wg_clients.get("rows"), list):
        logging.warning("Failed to retrieve WireGuard clients or invalid response")
        return set()

    instance_zones = parse_wg_instances_zones()

    # Build mapping: instance_name -> (uuid, ipv4_network, ipv6_network)
    server_info = {}
    for server in wg_servers["rows"]:
        name = server.get("name")
        uuid = server.get("uuid")
        tunneladdress = server.get("tunneladdress", "")

        if not name or not uuid or name not in instance_zones:
            continue

        # Parse tunneladdress: "10.99.99.254/24,fd10:0099:0099::254/64"
        ipv4_net = None
        ipv6_net = None

        for addr in tunneladdress.split(","):
            addr = addr.strip()
            if not addr:
                continue

            try:
                net = ipaddress.ip_network(addr, strict=False)
                if net.version == 4:
                    ipv4_net = net
                elif net.version == 6:
                    ipv6_net = net
            except ValueError:
                continue

        server_info[uuid] = {
            "name": name,
            "zone": instance_zones[name],
            "ipv4_net": ipv4_net,
            "ipv6_net": ipv6_net
        }

    # Process clients
    wg_matches = set()
    for client in wg_clients["rows"]:
        if client.get("enabled") != "1":
            continue

        name = client.get("name")
        servers = client.get("servers")  # UUID of the server instance
        tunneladdress = client.get("tunneladdress", "")

        if not name or not servers or servers not in server_info:
            continue

        server = server_info[servers]
        zone = server["zone"]

        # Parse client tunneladdress and filter for /32 and /128 that match server networks
        ipv4_addrs = []
        ipv6_addrs = []

        for addr in tunneladdress.split(","):
            addr = addr.strip()
            if not addr:
                continue

            try:
                # Check if it's a host address (/32 or /128)
                if addr.endswith("/32"):
                    ip = ipaddress.ip_address(addr.replace("/32", ""))
                    if ip.version == 4 and server["ipv4_net"] and ip in server["ipv4_net"]:
                        ipv4_addrs.append(ip.compressed)
                elif addr.endswith("/128"):
                    ip = ipaddress.ip_address(addr.replace("/128", ""))
                    if ip.version == 6 and server["ipv6_net"] and ip in server["ipv6_net"]:
                        ipv6_addrs.append(ip.compressed)
            except ValueError:
                continue

        # Create match entry for each IPv4 address (similar to DHCP matches)
        for ipv4 in ipv4_addrs:
            wg_matches.add((ipv4, tuple(ipv6_addrs), name, zone))

    return wg_matches

def sync_records(zones, match, zone_override=None, publish_gua_as_aaaa=False, force_ipv4=False):
    """Sync DNS records for a host (DHCP/SLAAC or WireGuard).

    Args:
        zones: List of (network, zone_name) tuples
        match: Tuple of (ipv4, ipv6s_tuple, hostname[, zone]) - zone is optional for WireGuard
        zone_override: Optional zone name (extracted from match[3] for WireGuard)
        publish_gua_as_aaaa: If True, publish GUA addresses as AAAA (for WireGuard)
        force_ipv4: If True, always publish IPv4 records regardless of DO_V4 setting (for WireGuard)
    """
    # For WireGuard matches: (ip4, ip6s, hostname, zone)
    # For DHCP matches: (ip4, ip6s, hostname)
    if zone_override or (len(match) == 4 and isinstance(match[3], str)):
        zone = zone_override or match[3]
        ip4, ip6s_tuple, hostname = match[0], match[1], match[2]
    else:
        zone = find_zone(zones, ipaddress.ip_address(match[0]))
        if zone is None:
            logging.warning("Could not find a DNS zone for " + match[0])
            return
        ip4, ip6s_tuple, hostname = match[0], match[1], match[2]

    if not hostname:
        logging.warning(f"No hostname found for {ip4}")
        return

    ip6s_all = [ipaddress.ip_address(x) for x in ip6s_tuple]

    # Separate IPv6 by scope/type
    ip6s_ula = [ip.compressed for ip in ip6s_all if isinstance(ip, ipaddress.IPv6Address) and ip.is_private and not ip.is_link_local]
    ip6s_gua = [ip.compressed for ip in ip6s_all if isinstance(ip, ipaddress.IPv6Address) and (not ip.is_private) and (not ip.is_link_local)]

    existing_records = get_existing_records(hostname, zone)
    existing_v4 = {ipaddress.ip_address(r["rData"]["ipAddress"]).compressed for r in existing_records if r["type"] == "A"}
    existing_v6 = {ipaddress.ip_address(r["rData"]["ipAddress"]).compressed for r in existing_records if r["type"] == "AAAA"}

    # For WireGuard (force_ipv4=True): always publish IPv4
    # For DHCP/SLAAC: only publish IPv4 if DO_V4 is enabled
    current_v4 = set([ipaddress.ip_address(ip4).compressed] if (force_ipv4 or DO_V4) else [])

    # For WireGuard: publish both ULA and GUA as AAAA
    # For DHCP/SLAAC: only publish ULA as AAAA
    if publish_gua_as_aaaa:
        current_v6 = set(ip6s_ula + ip6s_gua)
    else:
        current_v6 = set(ip6s_ula)

    # Cleanup: if there are historical AAAA records for GUA under hostname.zone, remove them
    # (only for DHCP/SLAAC mode)
    if not publish_gua_as_aaaa:
        for ip in (existing_v6 & set(ip6s_gua)):
            delete_record(zone, hostname, "AAAA", ip)

    # Delete outdated records (A/AAAA only)
    for ip in existing_v4 - current_v4:
        delete_record(zone, hostname, "A", ip)

    for ip in existing_v6 - current_v6:
        delete_record(zone, hostname, "AAAA", ip)

    # Add missing records
    for ip in current_v4 - existing_v4:
        add_record(zone, hostname, "A", ip)

    for ip in current_v6 - existing_v6:
        add_record(zone, hostname, "AAAA", ip)

    return zone, hostname, current_v4, ip6s_ula, ip6s_gua


def sync_ptrs(zone, hostname, current_v4, ip6s_ula, ip6s_gua, publish_gua_as_aaaa=False):
    """Explicitly sync PTR records for all given IPs.

    Called separately so PTR sync can be deferred to refresh cycles,
    except for newly seen IPs which always trigger an immediate PTR sync.
    """
    for ip in current_v4:
        add_ptr_only(zone, hostname, ip)

    for ip in ip6s_ula:
        add_ptr_only(zone, hostname, ip)

    # IPv6 GUA: PTR only (no AAAA!) - only for DHCP/SLAAC mode
    if not publish_gua_as_aaaa:
        for ip in ip6s_gua:
            add_ptr_only(zone, hostname, ip)

def run():
    if not VERIFY_HTTPS:
        urllib3.disable_warnings()

    previous_matches = set()
    previous_wg_matches = set()
    # Cache: maps match-tuple -> (zone, hostname, current_v4, ip6s_ula, ip6s_gua)
    # Used to avoid re-querying Technitium for PTR sync on unchanged matches
    ptr_cache: dict = {}
    wg_ptr_cache: dict = {}
    zones = []
    for z in DNS_ZONE_SUBNETS.split(","):
        zone = z.split("=")
        zones.append((ipaddress.ip_network(zone[0]), zone[1]))

    refresh_counter = 0

    while True:
        ndp = get_ndp()
        if ndp is None:
            logging.error("Error retrieving NDP table")
            time.sleep(CLOCK)
            continue
        leases = get_dhcp4_leases_v2()
        if leases is None:
            logging.error("Error retrieving DHCPv4 leases")
            time.sleep(CLOCK)
            continue
        matches = build_matches(ndp, leases)

        # Process new/changed matches - sync forward records AND PTRs immediately
        new_matches = matches - previous_matches
        for match in new_matches:
            result = sync_records(zones, match)
            if result:
                ptr_cache[match] = result
                sync_ptrs(*result)

        # Remove stale entries from PTR cache
        for gone in previous_matches - matches:
            ptr_cache.pop(gone, None)

        # Process WireGuard clients if enabled
        if ENABLE_WIREGUARD_DNS:
            wg_matches = process_wireguard_clients()
            new_wg_matches = wg_matches - previous_wg_matches
            for match in new_wg_matches:
                result = sync_records(zones, match, publish_gua_as_aaaa=True, force_ipv4=True)
                if result:
                    wg_ptr_cache[match] = result
                    sync_ptrs(*result, publish_gua_as_aaaa=True)

            for gone in previous_wg_matches - wg_matches:
                wg_ptr_cache.pop(gone, None)

            previous_wg_matches = wg_matches

        # Every REFRESH_CYCLE iterations, refresh ALL forward records and PTRs
        refresh_counter += 1
        if refresh_counter >= REFRESH_CYCLE:
            logging.info("Performing periodic refresh of all DNS records and PTRs")
            for match in matches:
                result = sync_records(zones, match)
                if result:
                    ptr_cache[match] = result
                    sync_ptrs(*result)
            if ENABLE_WIREGUARD_DNS:
                for match in previous_wg_matches:
                    result = sync_records(zones, match, publish_gua_as_aaaa=True, force_ipv4=True)
                    if result:
                        wg_ptr_cache[match] = result
                        sync_ptrs(*result, publish_gua_as_aaaa=True)
            refresh_counter = 0

        previous_matches = matches
        time.sleep(CLOCK)

def verify_env() -> bool:
    if not OPNSENSE_URL: return False
    if not OPNSENSE_API_KEY: return False
    if not OPNSENSE_API_SECRET: return False
    if not TECHNITIUM_URL: return False
    if not TECHNITIUM_TOKEN: return False
    if not DNS_ZONE_SUBNETS: return False
    return True

if __name__ == "__main__":
    logging.getLogger().setLevel(os.getenv("LOG_LEVEL", "INFO"))
    logging.info("loading environment...")

    if not verify_env():
        logging.error("Missing mandatory environment variables")
        exit(0)

    logging.info("Starting SLAACsense...")
    logging.info("OPNSENSE_URL: {}".format(OPNSENSE_URL))
    logging.info("TECHNITIUM_URL: {}".format(TECHNITIUM_URL))
    logging.info("VERIFY_HTTPS: {}".format(VERIFY_HTTPS))
    logging.info("ENABLE_WIREGUARD_DNS: {}".format(ENABLE_WIREGUARD_DNS))
    if ENABLE_WIREGUARD_DNS:
        logging.info("WG_INSTANCES_DNSZONES: {}".format(WG_INSTANCES_DNSZONES))
    run()
