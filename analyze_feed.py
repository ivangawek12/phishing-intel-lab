#!/usr/bin/env python3

import json
from pathlib import Path
from url_analyzer import analyze_url

DATA_DIR = Path("data")


def main():
    files = sorted(DATA_DIR.glob("phishstats_*.json"))

    if not files:
        print("[ERROR] No hay archivos de PhishStats en data/")
        return

    source_file = files[-1]

    with source_file.open(encoding="utf-8") as file:
        data = json.load(file)

    records = data.get("records", [])
    results = []

    for record in records:
        if not isinstance(record, dict):
            continue

        url = record.get("url")

        if not isinstance(url, str) or not url.strip():
            continue

        result = analyze_url(url)
        result["feed_date"] = record.get("date")
        results.append(result)

    output_file = DATA_DIR / "url_analysis.json"
    output_file.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Feed: {source_file}")
    print(f"URLs analizadas localmente: {len(results)}")
    print(f"Resultado: {output_file}")

    for result in results:
        print("\n" + "-" * 50)
        print(f"URL:    {result.get('input', 'N/D')}")
        print(f"Host:   {result.get('host', 'N/D')}")
        print(f"Ruta:   {result.get('path', 'N/D')}")


if __name__ == "__main__":
    main()
