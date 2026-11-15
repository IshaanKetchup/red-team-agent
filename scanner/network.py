
import nmap


def discover_hosts(network: str) -> list[dict]:
    """
    Discover active hosts on an authorised network.
    """

    scanner = nmap.PortScanner()

    #print(f"[*] Discovering hosts on {network}...")

    scanner.scan(hosts=network, arguments="-sn")

    hosts = []

    for host in scanner.all_hosts():
        host_data = {
            "ip": host,
            "status": scanner[host].state(),
            "hostname": scanner[host].hostname()
        }

        hosts.append(host_data)

    return hosts
