#!/usr/bin/env python3

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, unquote

OUTPUT_DIR = Path("data")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MAX_DEPTH = 3
MAX_DECODE_LEVELS = 3


def find_urls(text):
    """Extract candidate HTTP(S) URLs without network access."""
    pattern = r'https?://[^\s"\'<>]+'
    matches = re.findall(pattern, text, flags=re.IGNORECASE)

    # Remove common trailing punctuation from extracted candidates.
    return [
        item.rstrip(".,;)")
        for item in matches
    ]


def decode_parameter(value):
    """Decode a parameter incrementally and collect candidate URLs."""
    current = value
    candidates = []

    for level in range(1, MAX_DECODE_LEVELS + 1):
        urls = find_urls(current)

        for candidate in urls:
            candidates.append({
                "url": candidate,
                "decode_level": level,
            })

        decoded = unquote(current)

        if decoded == current:
            break

        current = decoded

    return candidates


def inspect_url(url, depth=0, seen=None, findings=None):
    """Parse a URL and recursively inspect nested URL candidates."""
    if seen is None:
        seen = set()

    if findings is None:
        findings = []

    indent = "  " * depth

    try:
        parsed = urlsplit(url)
        host = parsed.hostname
    except ValueError:
        print(f"{indent}[!] URL inválida")
        return findings

    if parsed.scheme.lower() not in ("http", "https") or not host:
        print(f"{indent}[!] No es una URL HTTP(S) válida")
        return findings

    if url in seen:
        print(f"{indent}[i] URL repetida; se evita un ciclo")
        return findings

    seen.add(url)

    item = {
        "url": url,
        "host": host.lower(),
        "path": parsed.path or "/",
        "depth": depth,
        "parameters": [],
        "nested_candidates": [],
    }
    findings.append(item)

    print(f"{indent}URL: {url}")
    print(f"{indent}Host: {host.lower()}")
    print(f"{indent}Path: {parsed.path or '/'}")

    if depth >= MAX_DEPTH:
        print(f"{indent}[i] Límite de profundidad alcanzado")
        return findings

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        parameter = {
            "name": key,
            "value": value,
            "nested_candidates": [],
        }
        item["parameters"].append(parameter)

        print(f"{indent}Parámetro: {key}")

        for candidate in decode_parameter(value):
            candidate_url = candidate["url"]

            # Avoid recording the same URL twice per parameter.
            if any(
                existing["url"] == candidate_url
                for existing in parameter["nested_candidates"]
            ):
                continue

            nested = {
                "url": candidate_url,
                "decode_level": candidate["decode_level"],
            }
            parameter["nested_candidates"].append(nested)
            item["nested_candidates"].append(nested)

            print(
                f"{indent}  Candidato anidado "
                f"(decodificación {candidate['decode_level']}): "
                f"{candidate_url}"
            )

            inspect_url(
                candidate_url,
                depth + 1,
                seen,
                findings,
            )

    return findings


def main():
    original_url = input("Pegá la URL para analizar localmente: ").strip()

    print("\n=== Análisis estático de URL ===")
    print("No se realizan peticiones HTTP ni consultas DNS.\n")

    findings = inspect_url(original_url)

    if not findings:
        print("[ERROR] No se pudo analizar una URL válida.")
        return

    report = {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "input_url": original_url,
        "method": "Local URL parsing; no HTTP requests",
        "url_visited": False,
        "content_downloaded": False,
        "findings": findings,
        "limitations": [
            "Los destinos anidados son candidatos extraídos del texto.",
            "No se verificó que ocurra una redirección real.",
            "La presencia de una URL no demuestra actividad maliciosa."
        ],
    }

    filename = (
        "redirects_"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + ".json"
    )
    output_file = OUTPUT_DIR / filename
    output_file.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\n[+] Informe guardado en: {output_file}")


if __name__ == "__main__":
    main()
