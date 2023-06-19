import socket
import sys
import subprocess
import time
import requests
import multiprocessing

def scan_port(ip, port):
    try:
        socket.create_connection((ip, port))
        return True
    except socket.error:
        return False

def get_known_ports():
    known_ports = []

    with open("known_ports.txt", "r") as f:
        for line in f:
            port = int(line.strip())
            known_ports.append(port)

    return known_ports

def get_service_version(port):
    services = {
        80: "HTTP",
        443: "HTTPS",
        8554: "RTSP"
    }

    try:
        r = requests.get("https://api.ipify.org/", timeout=1)
        ip_address = r.text

        p = subprocess.Popen(["nmap", "-p", str(port), ip_address], stdout=subprocess.PIPE)
        output = p.communicate()[0].decode("utf-8")
        version = re.search(r"Version: (.*)", output).group(1)
    except subprocess.CalledProcessError:
        version = "Unknown"

    return services.get(port, version)

def scan_cctv(ip):
    for port in known_ports:
        if scan_port(ip, port):
            if port == 8554:
                return True

    return False

def main():
    ip_range = sys.argv[1]
    timeout = int(sys.argv[2])

    start = time.time()

    with Pool(multiprocessing.cpu_count()) as pool:
        ip_addresses = pool.map(scan_port, ip_range.split("."))
        services = pool.map(get_service_version, ip_addresses)
        is_cctv = pool.map(scan_cctv, ip_addresses)

    for ip, service, is_cctv in zip(ip_addresses, services, is_cctv):
        if service == "Unknown":
            continue

        if scan_port(ip, port, timeout):
            print("Open port: {} ({})".format(port, service))

        if is_cctv:
            print("CCTV is running on IP address {}".format(ip))

    print("Scanning took {} seconds".format(time.time() - start))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scan_network.py <IP range> <timeout>")
        sys.exit(1)

    main()
