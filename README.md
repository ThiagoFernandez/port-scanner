# portScanner

Port scanner de línea de comandos construido en Python. Detecta puertos abiertos, cerrados y filtrados, captura banners de servicios, **adivina el sistema operativo del host** (OS fingerprinting) y exporta los resultados a JSON.

Proyecto de las Fases 1 y 2 del roadmap de Python para ciberseguridad: la base usa `socket`, threading y manejo de errores de red (Fase 1); la **v2** suma OS fingerprinting con paquetes crudos vía Scapy (Fase 2).

---

## Features

- **Tres estados de puerto:** `OPEN`, `CLOSED`, `FILTERED`
- **Multithreading** con `ThreadPoolExecutor` — escanea cientos de puertos en paralelo
- **Banner grabbing** — captura la respuesta del servicio en cada puerto abierto
- **Identificación de servicios** — mapea número de puerto a nombre (`ssh`, `http`, `ftp`, etc.)
- **OS fingerprinting (v2)** — infiere el SO del host (Linux / Windows / Cisco) por el TTL y la ventana TCP de un SYN/ACK, y estima los saltos de red
- **Output con colores** — verde para abiertos, rojo para cerrados, amarillo para filtrados
- **Exportación a JSON** — guarda los resultados con timestamp automático
- **Múltiples targets** — acepta un archivo `.txt` con hosts, uno por línea

---

## Instalación

```bash
git clone https://github.com/tu-usuario/portScanner.git
cd portScanner
pip install colorama scapy
```

---

## Uso

```bash
python scanner.py <host|archivo> <puerto_inicio> <puerto_fin>
```

> **OS fingerprinting:** usa raw sockets (Scapy), así que necesita privilegios. Corré la terminal **como administrador** (Windows, con **Npcap** instalado) o con `sudo` (Linux). Sin eso, el escaneo de puertos igual funciona pero el fingerprint se saltea. No lo pruebes contra `127.0.0.1`: Scapy sobre loopback se comporta mal.

### Ejemplos

```bash
# Escanear un host por hostname
python scanner.py scanme.nmap.org 1 1024

# Escanear por IP
python scanner.py 192.168.1.1 1 1024

# Escanear localhost
python scanner.py 127.0.0.1 1 9999

# Escanear múltiples hosts desde archivo
python scanner.py hosts.txt 1 1024
```

### Archivo de múltiples hosts (`hosts.txt`)

```
scanme.nmap.org
192.168.1.1
192.168.1.254
```

---

## Output

### Terminal

```
Target: scanme.nmap.org
Rango: 1-1024

=== Escaneando scanme.nmap.org ===
[+] 22 OPEN
[-] 23 CLOSED
[?] 25 FILTERED
[+] 80 OPEN
...

--- RESULTADO ---
Host: scanme.nmap.org (45.33.32.156)
Puertos escaneados: 1024
Puertos abiertos: 2
Lista de puertos abiertos:
- 1) Port: 22 | Service: ssh | Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
- 2) Port: 80 | Service: http | Banner:

Realizando OS Fingerprinting sobre puerto 80...
OS detectado: Linux | Confianza: 90% (a 22 saltos)

[+] Resultados guardados en results_scanme.nmap.org_2026-11-03_12-01-06.json
```

### JSON de salida

```json
{
    "raw_host": "scanme.nmap.org",
    "host": "45.33.32.156",
    "starting_port": 1,
    "ending_port": 1024,
    "scanned_ports": 1024,
    "open_ports": [
        {
            "port": 22,
            "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_6.6.1p1"
        },
        {
            "port": 80,
            "service": "http",
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache..."
        }
    ],
    "os_fingerprint": {
        "os": "Linux",
        "confidence": 90,
        "network_hops": 22
    },
    "time": 4.32
}
```

---

## Cómo funciona

### Detección de estado

`socket.connect_ex()` intenta establecer una conexión TCP e interpreta la respuesta:

| Respuesta del host | Estado | Significado |
|--------------------|--------|-------------|
| SYN-ACK (código 0) | `OPEN` | Hay un servicio escuchando |
| RST (`ECONNREFUSED`) | `CLOSED` | El puerto existe pero no hay servicio |
| Sin respuesta (timeout) | `FILTERED` | Un firewall está bloqueando el paquete |

### Banner grabbing

Para cada puerto abierto el scanner intenta dos estrategias:
1. Escuchar directamente — algunos servicios (SSH, FTP) mandan su banner al conectarse
2. Si no hay respuesta, enviar un `HEAD / HTTP/1.1` — estimula al servicio a responder (útil para HTTP)

El timeout de conexión (0.5s) es independiente del timeout de banner (1.0s), lo que permite capturar banners lentos sin afectar la velocidad del escaneo.

### Threading

Usa `ThreadPoolExecutor(max_workers=200)` con `as_completed()` para procesar resultados en tiempo real a medida que cada hilo termina.

### OS fingerprinting (v2)

`socket.connect_ex()` deja que el kernel haga el handshake, así que el SYN/ACK del host —con su TTL y su ventana— nunca llega al programa. Para leer esos campos la v2 manda un SYN crudo con Scapy (`sr1`) a un puerto ya abierto y analiza la respuesta:

| Señal | De dónde sale | Qué dice |
|-------|---------------|----------|
| **TTL** | capa IP del SYN/ACK | Se redondea al origen más cercano: 64 → Linux/Unix, 128 → Windows, 255 → Cisco IOS/Solaris. Los saltos se estiman como `origen − observado`. |
| **Ventana TCP** | capa TCP del SYN/ACK | Desempate: ajusta la confianza según valores característicos de cada SO. Señal secundaria — con window scaling es menos fiable que el TTL. |

> La mayoría de los routers hogareños corren **Linux embebido** (TTL 64), no TTL 255 — la firma 255 es de equipo Cisco enterprise.

---

## Dependencias

| Librería | Instalación | Uso |
|---------|------------|-----|
| `colorama` | `pip install colorama` | Colores en terminal cross-platform |
| `scapy` | `pip install scapy` | Paquetes crudos (SYN/ACK) para el OS fingerprinting — v2 |
| `socket` | stdlib | Conexiones TCP, resolución DNS, servicios |
| `concurrent.futures` | stdlib | ThreadPoolExecutor |
| `errno` | stdlib | Códigos de error cross-platform |
| `json`, `os`, `sys`, `time`, `datetime` | stdlib | Utilidades generales |

---

## Consideraciones legales

Usar este scanner solo en redes y sistemas de tu propiedad o sobre los que tenés autorización explícita. El port scanning sin autorización puede ser ilegal dependiendo de la jurisdicción.

Para practicar de forma legal: [scanme.nmap.org](http://scanme.nmap.org) es un servidor mantenido por el equipo de Nmap específicamente para este propósito.

---

## Limitaciones conocidas

- No soporta IPv6
- `max_workers=200` puede saturar redes lentas — reducir si hay falsos FILTERED
- Los hosts de un archivo se escanean secuencialmente
- El banner se trunca a 1KB
- El OS fingerprinting necesita privilegios de admin/root y un puerto abierto; los equipos que filtran el SYN crafteado (routers con anti-flood) no devuelven veredicto
- El fingerprint por TTL es heurístico y **falsificable**: un host puede cambiar su TTL inicial para mentir

---

*Parte del roadmap de Python para Ciberseguridad — Fases 1 y 2*
