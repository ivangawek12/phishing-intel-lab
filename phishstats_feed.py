#!/usr/bin/env python3

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_URL = (
    "https://api.phishstats.info/api/phishing"
    "?_sort=-date&_p=1&_size=10"
)

OUTPUT_DIR = Path("data")
OUTPUT_DIR.mkdir(exist_ok=True)


def main():
    request = urllib.request.Request(
        API_URL,
        headers={"User-Agent": "PhishingIntelLab/0.1"},
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            records = json.loads(response.read().decode("utf-8"))
    except Exception as error:
        print(f"[ERROR] No se pudo consultar PhishStats: {error}")
        return

    if not isinstance(records, list):
        print("[ERROR] La API no devolvió una lista JSON.")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_file = OUTPUT_DIR / f"phishstats_{timestamp}.json"

    result = {
        "source": "PhishStats",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "records": records,
    }

    output_file.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\nFuente: PhishStats")
    print(f"Registros recibidos: {len(records)}")
    print(f"Archivo guardado: {output_file}\n")

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue

        print(f"[{index}]")
        print(f"  Fecha:   {record.get('date', 'N/D')}")
        print(f"  URL:     {record.get('url', 'N/D')}")
        print(f"  IP:      {record.get('ip', 'N/D')}")
        print(f"  País:    {record.get('countrycode', 'N/D')}")
        print()


if __name__ == "__main__": main()
