# SLAACsense

SLAACsense streamlines the process of configuring DNS records on OPNsense routers using Technitium DNS Server.

Designed to enhance network management, the tool automatically defines DNS A, AAAA, and PTR records for each device connected to the network based on its DHCPv4 hostname.

By leveraging the (dnsmasq) DHCPv4 lease information and mapping it to the MAC address, the tool navigates the NDP table to retrieve IPv6 addresses associated with each host. Subsequently, it configures the DNS records accordingly, providing a seamless solution for maintaining an up-to-date and accurate DNS configuration.

## Usage:

Define the environment variables in the docker-compose file, then run: `docker compose up -d`

### Environment variables:

| Variable Name                          | Description                                                                                                  | Example Value                                                          |
|----------------------------------------|--------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `OPNSENSE_URL`                         | The base URL of your OPNsense instance                                                                       | http://192.168.1.1 (required)                                          |
| `OPNSENSE_API_KEY`                     | OPNsense API key                                                                                             | `your_opnsense_api_key` (required)                                     |
| `OPNSENSE_API_SECRET`                  | OPNsense API secret                                                                                          | `a_very_secret_token` (required)                                       |
| `TECHNITIUM_URL`                       | The base URL of your Technitium DNS instance                                                                 | `dns.myawesomehome.home.arpa` (required)                               |
| `TECHNITIUM_TOKEN`                     | Technitium DNS token                                                                                         | `another_very_secret_token` (required)                                 |
| `DNS_ZONE_SUBNETS`                     | Comma separated DNS zones and IPv4 subnet                                                                    | `192.168.1.0/24=lan.home.arpa,192.168.2.0/24=dmz.home.arpa` (required) |
| `DO_V4`                                | If set to true, A records will be configured, otherwise only AAAA records are configured                     | `false` (defaults to false)                                            |
| `IGNORE_LINK_LOCAL`                    | If set to true, link local IPv6 addresses wil be ignored                                                     | `true` (defaults to true)                                              |
| `VERIFY_HTTPS`                         | Verify OPNsense and Technitium's SSL certificates                                                            | `true` (defaults to true)                                              |
| `CLOCK`                                | Interval between updates (in seconds)                                                                        | `30` (defaults to 30)                                                  |
| `REFRESH_CYCLE`                        | How often to refresh all DNS records (in cycles)                                                             | `120` (defaults to 1440, 12 hours with default CLOCK)                  |
| `TECHNITIUM_PTR_CATALOG`               | (Optional) Catalog zone to add auto-created reverse zones to                                                  | `cluster-catalog.dns.local` (defaults to shown value)                  |
| `TECHNITIUM_USE_SOA_SERIAL_DATE_SCHEME`| (Optional) Enable SOA serial date scheme when auto-creating reverse zones                                     | `true` (defaults to true)                                              |
| `TECHNITIUM_IPV6_PTR_PREFIXLEN`        | (Optional) IPv6 reverse zone prefix length to create (must be divisible by 4, e.g. 48/56/64). Default is /64 | `64` (defaults to 64)                                                  |
| `TECHNITIUM_ZONE_CREATE_FALLBACK_NO_CATALOG` | (Optional) Retry creating reverse zones without catalog if catalog permissions are missing               | `true` (defaults to true)                                              |

### Note
You have to create the corresponding forward DNS zones in the Technitium dashboard (primary or conditional forwarder zones).

Reverse zones are required for PTR creation. If a reverse zone is missing, SLAACsense will try to auto-create it on Technitium (Primary zone), using:
- `useSoaSerialDateScheme=true`
- `catalog=cluster-catalog.dns.local` (configurable via `TECHNITIUM_PTR_CATALOG`)

If the Technitium token does not have permissions to use the catalog zone, SLAACsense will automatically retry creating the reverse zone without a catalog (configurable via `TECHNITIUM_ZONE_CREATE_FALLBACK_NO_CATALOG`).

### Contributing:
I welcome contributions! Feel free to submit issues, feature requests, or pull requests.

For example, you may add the support for other DNS servers, like Bind, and other routing platforms, like pfSense and OpenWrt. 

### License:
This tool is released under the MIT license. See the LICENSE file for details.