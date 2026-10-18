import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path("data")


def main():
    files = list(DATA_DIR.glob("ioc_*.json"))

    if not files:
        print("No se encontraron archivos data/ioc_*.json")
        return

    source = max(files, key=lambda p: p.stat().st_mtime)

    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error leyendo el JSON: {exc}")
        return

    infrastructure = data.get("infrastructure", [])
    ips = data.get("dns_a_records", [])

    asns = Counter(
        item.get("asn", "Desconocido")
        for item in infrastructure
    )
    organizations = Counter(
        item.get("as_name", "Desconocida")
        for item in infrastructure
    )
    countries = Counter(
        item.get("country", "Desconocido")
        for item in infrastructure
    )
    prefixes = sorted({
        item.get("bgp_prefix")
        for item in infrastructure
        if item.get("bgp_prefix")
    })

    lines = [
        "# Ficha de contexto de infraestructura",
        "",
        f"- Generada (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"- Fuente: `{source}`",
        "",
        "## 1. Observaciones",
        "",
        f"- Host consultado: `{data.get('input_host', 'No informado')}`",
        f"- IPv4 registradas en el resultado DNS: {len(ips)}",
        f"- Registros de enriquecimiento ASN: {len(infrastructure)}",
        "",
        "### Direcciones IPv4",
        "",
    ]

    lines.extend(f"- `{ip}`" for ip in ips)
    lines.extend(["", "### ASN observados", ""])

    if asns:
        lines.extend(
            f"- ASN `{asn}`: {count} registro(s)"
            for asn, count in sorted(asns.items())
        )
    else:
        lines.append("- No hay datos ASN disponibles.")

    lines.extend(["", "### Organizaciones declaradas", ""])

    if organizations:
        lines.extend(
            f"- {name}: {count} registro(s)"
            for name, count in organizations.items()
        )
    else:
        lines.append("- No hay organizaciones registradas.")

    lines.extend(["", "### Países informados", ""])

    if countries:
        lines.extend(
            f"- `{country}`: {count} registro(s)"
            for country, count in countries.items()
        )
    else:
        lines.append("- No hay países informados.")

    lines.extend(["", "### Prefijos BGP", ""])

    if prefixes:
        lines.extend(f"- `{prefix}`" for prefix in prefixes)
    else:
        lines.append("- No hay prefijos BGP informados.")

    lines.extend([
        "",
        "## 2. Inferencias limitadas",
        "",
        "- Las IP y sus asociaciones ASN reflejan los datos registrados por las fuentes consultadas.",
        "- Si varias IP comparten ASN u organización, existe una asociación de infraestructura declarada.",
        "- Los resultados DNS pueden variar con el tiempo y según la ubicación del resolver.",
        "",
        "## 3. No determinado",
        "",
        "- Si el hostname o la URL son maliciosos.",
        "- Quién controla efectivamente el hostname o la ruta consultada.",
        "- Si hubo redirecciones HTTP reales.",
        "- Si las IP alojan contenido malicioso.",
        "- La intención del operador y la reputación actual del indicador.",
        "",
        "## 4. Evaluación",
        "",
        "**Estado:** contexto de infraestructura disponible; reputación maliciosa no determinada.",
        "",
        "No asignar una etiqueta de malware o phishing únicamente por ASN, país, proveedor o cantidad de IP.",
        "",
    ])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = DATA_DIR / f"infrastructure_{timestamp}.md"
    output.write_text("\n".join(lines), encoding="utf-8")

    print("Ficha generada.")
    print(f"Fuente: {source}")
    print(f"Salida: {output}")
    print()
    print("Para leerla sin visor interactivo:")
    print(f"cat {output}")


if __name__ == "__main__":
    main()
