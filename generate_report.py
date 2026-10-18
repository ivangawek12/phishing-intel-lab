import json
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path("data")


def humanize(key):
    return key.replace("_", " ").replace("-", " ").strip().capitalize()


def render_value(value, level=0):
    indent = "  " * level

    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            lines.append(f"{indent}- **{humanize(str(key))}:**")
            if isinstance(item, (dict, list)):
                lines.append(render_value(item, level + 1))
            else:
                lines.append(f"{indent}  {format_value(item)}")
        return "\n".join(lines)

    if isinstance(value, list):
        if not value:
            return f"{indent}- Sin datos registrados."
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{indent}-")
                lines.append(render_value(item, level + 1))
            else:
                lines.append(f"{indent}- {format_value(item)}")
        return "\n".join(lines)

    return f"{indent}{format_value(value)}"


def format_value(value):
    if value is None:
        return "No informado"
    if isinstance(value, bool):
        return "Sí" if value else "No"
    if isinstance(value, str):
        return value.replace("\n", " ")
    return str(value)


def main():
    files = list(DATA_DIR.glob("analysis_*.json"))

    if not files:
        print("No se encontraron archivos data/analysis_*.json.")
        print("Ejecutá primero: python3 analyze_ioc.py")
        return

    source = max(files, key=lambda path: path.stat().st_mtime)

    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"No se pudo leer el análisis: {exc}")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = DATA_DIR / f"report_{timestamp}.md"

    lines = [
        "# Informe de análisis pasivo de IOC",
        "",
        f"- **Fecha de generación (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Archivo fuente:** `{source}`",
        "- **Método:** análisis sintáctico local y enriquecimiento de infraestructura.",
        "- **Acceso al sitio:** no realizado por este generador de informes.",
        "- **Descarga de contenido:** no realizada por este generador de informes.",
        "",
        "> Este informe documenta observaciones técnicas. La presencia de un dominio, IP, proveedor de hosting o ASN no demuestra por sí sola actividad maliciosa.",
        "",
        "## Datos del análisis",
        "",
    ]

    if isinstance(data, dict):
        for key, value in data.items():
            lines.append(f"### {humanize(str(key))}")
            lines.append("")
            lines.append(render_value(value))
            lines.append("")
    else:
        lines.append(render_value(data))
        lines.append("")

    lines.extend([
        "## Evaluación y límites",
        "",
        "- **Hechos observados:** son los valores registrados en el JSON fuente; pueden cambiar con el tiempo.",
        "- **Relaciones inferidas:** una URL encontrada dentro de un parámetro es un candidato extraído, no una redirección confirmada.",
        "- **Atribución:** un ASN o proveedor identifica una asociación de infraestructura, no necesariamente al operador del sitio.",
        "- **Alcance:** este informe no verifica el comportamiento HTTP, el contenido de la página, la reputación externa ni la titularidad real del dominio.",
        "- **Siguiente validación:** contrastar los indicadores con fuentes independientes y conservar la fecha de cada observación.",
        "",
        "## Archivo fuente",
        "",
        f"`{source}`",
        "",
    ])

    output.write_text("\n".join(lines), encoding="utf-8")
    print("Informe generado correctamente.")
    print(f"Fuente:   {source}")
    print(f"Reporte:  {output}")
    print()
    print("Para leerlo:")
    print(f"  less {output}")


if __name__ == "__main__":
    main()
