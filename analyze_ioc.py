#!/usr/bin/env python3

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from inspect_redirects import inspect_url

OUTPUT_DIR = Path("data")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def parse_input(raw):
    if not raw or any(char.isspace() for char in raw):
        raise ValueError("Entrada vacía o con espacios.")

    candidate = raw if "://" in raw else "//" + raw

    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("URL o hostname inválido.") from None

    if not host:
        raise ValueError("No se encontró un hostname.")

    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Solo se admiten URL HTTP o HTTPS.")

    if port is not None:
        raise ValueError("No se admiten puertos explícitos.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("No se admiten credenciales.")

    host = host.rstrip(".").lower()
    labels = host.split(".")

    if (
        len(host) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not label.isascii()
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
            for label in labels
        )
    ):
        raise ValueError("Formato de hostname inválido.")

    return host


def resolve_ipv4(host):
    output = run_command(["dig", "+short", "A", host])
    ips = []

    for line in output.splitlines():
        parts = line.split(".")
        try:
            if len(parts) == 4 and all(
                0 <= int(part) <= 255 for part in parts
            ):
                ips.append(line)
        except ValueError:
            continue

    return sorted(set(ips))


def lookup_asn(ip):
    output = run_command(
        ["whois", "-h", "whois.cymru.com", f" -v {ip}"]
    )

    for line in output.splitlines():
        if "|" not in line or line.lstrip().startswith("AS"):
            continue

        fields = [field.strip() for field in line.split("|")]

        if len(fields) >= 7 and fields[1] == ip:
            return {
                "ip": fields[1],
                "asn": fields[0],
                "bgp_prefix": fields[2],
                "country": fields[3],
                "registry": fields[4],
                "allocated": fields[5],
                "as_name": fields[6],
            }

    return {
        "ip": ip,
        "error": "No se obtuvo información ASN.",
    }


def main():
    print("=== Passive IOC Analysis ===")
    print("No se visita la URL ni se descarga su contenido.\n")

    raw = input("Ingresá una URL HTTP(S) o hostname: ").strip()

    try:
        host = parse_input(raw)
    except ValueError as error:
        print(f"[ERROR] {error}")
        return

    print(f"\n[1/3] Hostname extraído: {host}")
    print("[2/3] Analizando parámetros y URL anidadas...")

    findings = inspect_url(raw)

    print("\n[3/3] Consultando DNS y ASN del hostname principal...")
    ips = resolve_ipv4(host)
    infrastructure = []

    for ip in ips:
        print(f"[+] ASN: {ip}")
        infrastructure.append(lookup_asn(ip))

    report = {
        "source": "Passive IOC Analysis",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "input": raw,
        "input_host": host,
        "url_visited": False,
        "content_downloaded": False,
        "dns_a_records": ips,
        "infrastructure": infrastructure,
        "url_findings": findings,
        "limitations": [
            "Las URL anidadas son candidatos extraídos sintácticamente.",
            "No se verificó ninguna redirección real.",
            "DNS y ASN describen observaciones de infraestructura.",
            "La información no demuestra por sí sola actividad maliciosa."
        ],
    }

    filename = (
        "analysis_"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + ".json"
    )
    output_file = OUTPUT_DIR / filename

    output_file.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n=== Resumen ===")
    print(f"Hostname principal: {host}")
    print(f"IPv4 encontradas: {len(ips)}")
    print(f"Candidatos URL analizados: {len(findings)}")
    print(f"Informe consolidado: {output_file}")


if __name__ == "__main__":
    main()
