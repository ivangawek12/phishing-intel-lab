#!/usr/bin/env python3

from urllib.parse import urlsplit, parse_qsl


def analyze_url(url):
    url = url.strip()
    if not url:
        return {"error": "URL vacía"}

    candidate = url if "://" in url else "//" + url

    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname

        if not host:
            return {"input": url, "error": "No se pudo identificar el host"}

        return {
            "input": url,
            "scheme": parsed.scheme or "no especificado",
            "host": host.lower(),
            "port": parsed.port,
            "path": parsed.path or "/",
            "query_parameters": [
                key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            "fragment_present": bool(parsed.fragment),
        }
    except ValueError:
        return {"input": url, "error": "URL inválida"}


if __name__ == "__main__":
    test_url = input("Pegá una URL para analizar localmente: ")
    result = analyze_url(test_url)

    for key, value in result.items():
        print(f"{key}: {value}")
