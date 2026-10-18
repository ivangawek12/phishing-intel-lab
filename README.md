# Phishing Intel Lab

Local-first lab for passive phishing URL and infrastructure analysis.

## Capabilities
- Local URL parsing without visiting the target.
- Nested URL candidate extraction.
- DNS resolution and ASN/BGP enrichment.
- Consolidated IOC analysis in JSON.
- Markdown reporting.
- Separation of observations, inferences, and unknowns.

## Scripts
- `phishstats_feed.py`: retrieves a public phishing feed.
- `url_analyzer.py`: parses URL components locally.
- `analyze_feed.py`: processes feed URLs.
- `inspect_redirects.py`: extracts nested URL candidates.
- `enrich_ioc.py`: enriches hostnames with DNS and ASN data.
- `analyze_ioc.py`: consolidates IOC analysis.
- `generate_report.py`: generates Markdown reports.
- `classify_infrastructure.py`: documents infrastructure context.

## Requirements
Python 3, `dig`, `whois`, and internet access for external feed/DNS/ASN queries.

## Safety and limitations
- Local URL parsing does not visit the target website.
- DNS and ASN enrichment generate external queries.
- Nested URL extraction is heuristic and does not confirm HTTP redirects.
- An ASN, provider, country, or IP alone does not prove malicious activity.
- Experimental defensive learning lab; not a production verdict system.

## Data handling
Generated JSON and Markdown reports are excluded from Git by default. Review files before publication.
