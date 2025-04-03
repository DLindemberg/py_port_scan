import socket
from concurrent.futures import ThreadPoolExecutor

def get_dns_details(target):
    try:
        addr_info = socket.getaddrinfo(target, None)
        hostname, aliases, ipaddrlist = socket.gethostbyaddr(addr_info[0][4][0])
        return hostname, aliases, ipaddrlist, addr_info
    except socket.gaierror as e:
        print(f"Erro ao obter informações DNS: {e}")
        return None, [], [], None

def get_service_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            return banner.decode().strip()
    except Exception as e:
        return f"Serviço não identificado, erro: {e}"

def scan_port(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = get_service_banner(ip, port)
            results[port] = f"Aberta ({banner})"
    except:
        results[port] = "Fechada"

def print_ports_status(ip, results, hostname=None):
    header = f"\nIP: {ip} | Nome do host: {hostname}" if hostname else f"\nIP: {ip}"
    print(header)
    print("-" * 100)
    for port, status in sorted(results.items()):
        print(f"Porta {port}: {status}")
    print("-" * 100)

def scan_important_ports(ip):
    important_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080]
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        for port in important_ports:
            executor.submit(scan_port, ip, port, results)
        executor.shutdown(wait=True)
    return results

def find_subdomains(domain):
    common_subdomains = ['www', 'mail', 'ftp', 'blog', 'webmail', 'server', 'api', 'test', 'dev']
    found_subdomains = []
    for subdomain in common_subdomains:
        fqdn = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found_subdomains.append((fqdn, ip))
        except socket.gaierror:
            continue
    return found_subdomains

def main():
    print("Digite o IP ou domínio para escanear as portas:")
    while True:
        target = input("\nIP/Domínio: ")
        hostname, aliases, ipaddrlist, addr_info = get_dns_details(target)
        if not hostname:
            print("Falha ao resolver o IP/Domínio, tente outro.")
            continue

        subdomains = find_subdomains(target)
        results = scan_important_ports(addr_info[0][4][0])
        print_ports_status(addr_info[0][4][0], results, hostname)
        
        if subdomains:
            print("\nSubdomínios encontrados:")
            for subdomain, ip in subdomains:
                print(f"{subdomain} -> {ip}")
        else:
            print("Nenhum subdomínio adicional encontrado.")

        if input("\nDeseja verificar mais algum IP ou domínio? (s/n): ").lower() != 's':
            print("Ok. Até mais!")
            break

if __name__ == "__main__":
    main()
