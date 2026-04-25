import sys
import socket
import time
import errno
import json
import os
from colorama import Fore, Style, init
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_hosts(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_time():
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d_%H-%M-%S")
    return current_time

def create_dict(raw_host, host, puerto_inicial, puerto_fin, total, open_ports, elapsed):
    return {
        "raw_host": raw_host,
        "host": host,
        "starting_port": puerto_inicial,
        "ending_port": puerto_fin,
        "scanned_ports": total,
        "open_ports": [
            {
                "port": p,
                "service": s,
                "banner": b
            } for (p, s, b) in open_ports
        ],
        "time": elapsed
    }

def save_results(data, raw_host):
    file_name = "results_"+raw_host+"_" + get_time() + ".json"

    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    
    print(f"\n[+] Resultados guardados en {file_name}")


def validate_args():
    if len(sys.argv) != 4:
        print("Uso: python scanner.py <host|archivo> <puerto_inicio> <puerto_fin>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        p1 = int(sys.argv[2])
        p2 = int(sys.argv[3])
    except ValueError:
        print("Los puertos deben ser numéricos")
        sys.exit(1)

    puerto_inicio = min(p1, p2)
    puerto_fin = max(p1, p2)

    if not (0 <= puerto_inicio <= 65535 and 0 <= puerto_fin <= 65535):
        print("Los puertos deben estar entre 0 y 65535")
        sys.exit(1)

    print(f"Target: {target}")
    print(f"Rango: {puerto_inicio}-{puerto_fin}")

    return target, puerto_inicio, puerto_fin


def scan_port(host, raw_host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))

            if result == 0:
                banner = ""
                try:
                    s.settimeout(1.0)
                    data = s.recv(1024)
                    if data:
                        banner = data.decode(errors='ignore').strip()
                    else:
                        request = f"HEAD / HTTP/1.1\r\nHost: {raw_host}\r\nConnection: close\r\n\r\n"
                        s.sendall(request.encode())
                        data = s.recv(1024)
                        if data:
                            banner = data.decode(errors='ignore').strip()
                except (socket.timeout, OSError):
                    pass

                return (port, "OPEN", banner)

            elif result in (errno.ECONNREFUSED, 10061):  # Linux + Windows
                return (port, "CLOSED", "")

            else:
                return (port, "FILTERED", "")

    except OSError:
        return (port, "FILTERED", "")


def scan_ports_threaded(host, raw_host, puerto_inicio, puerto_fin):
    start_time = time.time()

    puertos = range(puerto_inicio, puerto_fin + 1)
    abiertos = []

    with ThreadPoolExecutor(max_workers=200) as executor:
        futuros = {executor.submit(scan_port, host, raw_host, p): p for p in puertos}

        for future in as_completed(futuros):
            port, estado, banner = future.result()

            if estado == "OPEN":
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"

                print(f"{Fore.GREEN}[+] {port} OPEN{Style.RESET_ALL}")
                abiertos.append((port, service, banner))

            elif estado == "CLOSED":
                print(f"{Fore.RED}[-] {port} CLOSED{Style.RESET_ALL}")

            else:
                print(f"{Fore.YELLOW}[?] {port} FILTERED{Style.RESET_ALL}")

    end_time = time.time()
    return abiertos, start_time, end_time


def main():
    target, puerto_inicio, puerto_fin = validate_args()

    if os.path.isfile(target):
        targets = load_hosts(target)
    else:
        targets = [target]

    for raw_host in targets:
        print(f"\n=== Escaneando {raw_host} ===")

        try:
            host = socket.gethostbyname(raw_host)
        except socket.gaierror:
            print(f"{Fore.RED}Host inválido: {raw_host}{Style.RESET_ALL}")
            continue

        open_ports, start_time, end_time = scan_ports_threaded(
            host, raw_host, puerto_inicio, puerto_fin
        )

        total_puertos = puerto_fin - puerto_inicio + 1

        print("\n--- RESULTADO ---")
        print(f"Host: {raw_host} ({host})")
        print(f"Puertos escaneados: {total_puertos}")
        print(f"Puertos abiertos: {len(open_ports)}")

        if open_ports:
            print("Lista de puertos abiertos:")
            for idx, (port, service, banner) in enumerate(open_ports, start=1):
                print(f"- {idx}) Port: {port} - Service: {service} - Banner: {banner}")

        print(f"Tiempo total: {end_time - start_time:.2f} segundos")

        data = create_dict(
            raw_host,
            host,
            puerto_inicio,
            puerto_fin,
            total_puertos,
            open_ports,
            end_time - start_time
        )

        save_results(data, raw_host)

if __name__ == "__main__":
    main()
