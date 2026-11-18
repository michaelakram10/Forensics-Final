#!/usr/bin/env python3
"""export_pdf.py -> report/FINAL_REPORT.pdf and report/PRESENTATION.pdf

pandoc is not installed, so this uses the Python `markdown` package plus WeasyPrint.
Image paths in the Markdown are resolved relative to the project root via <base href>.
"""
from pathlib import Path
import markdown
from weasyprint import HTML

ROOT = Path(__file__).resolve().parents[1]
CSS = """
@page { size: A4; margin: 18mm 16mm; @bottom-center { content: counter(page); font-size: 8pt; color:#666; } }
body { font-family: "DejaVu Sans", sans-serif; font-size: 9.2pt; line-height:1.4; color:#1a1a1a; }
h1 { font-size: 19pt; color:#123a5e; border-bottom:2px solid #123a5e; padding-bottom:4px; }
h2 { font-size: 14pt; color:#123a5e; border-bottom:1px solid #bbb; margin-top:18px; }
h3 { font-size: 11.5pt; color:#205b8a; margin-top:14px; }
h4 { font-size: 10pt; color:#205b8a; }
code { font-family:"DejaVu Sans Mono", monospace; font-size:8pt; background:#f2f4f7; }
pre { background:#f2f4f7; border:1px solid #d8dee6; padding:7px; overflow-wrap:anywhere; font-size:7.4pt; }
pre code { background:none; }
table { border-collapse:collapse; width:100%; font-size:8pt; margin:8px 0; }
th, td { border:1px solid #b9c4d0; padding:4px 5px; vertical-align:top; }
th { background:#e8eef5; text-align:left; }
img { max-width:100%; border:1px solid #ccc; margin:6px 0; }
blockquote { border-left:3px solid #888; padding-left:10px; color:#444; }
.slide { page-break-before:always; }
.slide h2 { font-size:16pt; }
"""


def convert(md_name, pdf_name, title):
    src = ROOT / "report" / md_name
    body = src.read_text()
    if md_name == "PRESENTATION.md":
        body = body.replace("## Presenter deck\n\n", "")
    html_body = markdown.markdown(body, extensions=["tables", "fenced_code", "sane_lists"])
    if md_name == "PRESENTATION.md":
        # Each `---` in the deck is a slide separator. Drop the rules and start a new
        # page at every slide heading except the first (which shares the title page).
        html_body = html_body.replace("<hr />", "").replace("<hr>", "")
        head, sep, tail = html_body.partition("<h2>")
        if sep:
            html_body = head + sep + tail.replace("<h2>", '<h2 class="slide">')
    doc = (f'<!doctype html><html><head><meta charset="utf-8">'
           f'<base href="{ROOT.as_uri()}/"><title>{title}</title>'
           f'<style>{CSS}</style></head><body>{html_body}</body></html>')
    out = ROOT / "report" / pdf_name
    HTML(string=doc, base_url=str(ROOT) + "/").write_pdf(str(out))
    print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    convert("FINAL_REPORT.md", "FINAL_REPORT.pdf", "Forensic Report - Project 09")
    if (ROOT / "report/PRESENTATION.md").exists():
        convert("PRESENTATION.md", "PRESENTATION.pdf", "Presentation - Project 09")
