import nmap


def scan_services(target_ip: str) -> list[dict]:
    scanner = nmap.PortScanner()

    print(f"[*] Enumerating services on {target_ip}...")

    scanner.scan(
        hosts=target_ip,
        ports="1-1024",
        arguments="-sV --version-light"
    )

    if target_ip not in scanner.all_hosts():
        raise RuntimeError(
            f"Nmap did not detect {target_ip} as reachable."
        )

    if scanner[target_ip].state() != "up":
        raise RuntimeError(
            f"Nmap reports {target_ip} is not up."
        )

    services = []

    for protocol in scanner[target_ip].all_protocols():
        for port in scanner[target_ip][protocol].keys():

            details = scanner[target_ip][protocol][port]

            services.append({
                "host_ip": target_ip,
                "port": port,
                "protocol": protocol,
                "service": details.get("name", ""),
                "product": details.get("product", ""),
                "version": details.get("version", "")
            })

    return services
