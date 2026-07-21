import sys
import csv
import json
import os
import re
import base64
import argparse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Union


VT_API_KEY = "Please enter your virustotal key."

VT_ENDPOINTS = {
    "ip": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "hash": "https://www.virustotal.com/api/v3/files/{}",
    "domain": "https://www.virustotal.com/api/v3/domains/{}",
    "url": "https://www.virustotal.com/api/v3/urls/{}",
}

THREAD_OPTIONS = [1, 3, 5, 8]

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def defang(value: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        parts = value.rsplit(".", 1)
        if len(parts) == 2:
            return f"{parts[0]}[.]{parts[1]}"
        return value
    if ioc_type == "domain":
        return value.replace(".", "[.]", 1)
    if ioc_type == "url":
        if value.startswith("https://"):
            return "hxxps[://]" + value[8:]
        if value.startswith("http://"):
            return "hxxp[://]" + value[7:]
        return value
    return value


class Tee:
    def __init__(self, filepath: str):
        self.file = open(filepath, "w")
        self.stdout = sys.stdout

    def write(self, text: str):
        self.stdout.write(text)
        self.file.write(text)

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def close(self):
        self.file.close()


def detect_type(value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if IP_PATTERN.match(value):
        return "ip"
    if "." in value:
        return "domain"
    return "hash"


def encode_url_for_vt(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check(value: str, ioc_type: str) -> dict:
    if ioc_type == "url":
        value_id = encode_url_for_vt(value)
    else:
        value_id = value
    url = VT_ENDPOINTS[ioc_type].format(value_id)
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def read_items_from_file(filepath: str) -> list[str]:
    items = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(line)
    return items


def extract_result(value: str, ioc_type: str, data: dict) -> dict:
    value = defang(value, ioc_type)
    attrs = data["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    undetected = stats["undetected"]

    total = malicious + suspicious + harmless + undetected
    if malicious > 0:
        result_str = f"MALICIOUS ({malicious}/{total})"
    elif suspicious > 0:
        result_str = f"SUSPICIOUS ({suspicious} engines)"
    else:
        result_str = "CLEAN"

    threat_label = None
    categories_str = None
    family_label = None

    if malicious > 0 or suspicious > 0:
        raw = attrs.get("popular_threat_category")
        if isinstance(raw, dict):
            vals = [str(v) for v in raw.values() if v]
            if vals:
                threat_label = ", ".join(vals)
        elif isinstance(raw, list):
            threat_label = ", ".join(str(v) for v in raw if v)
        elif raw:
            threat_label = str(raw)

        if not threat_label:
            raw2 = attrs.get("popular_threat_label")
            if raw2:
                threat_label = str(raw2)

        if not threat_label and ioc_type == "hash":
            yara = attrs.get("crowdsourced_yara_results", [])
            if yara:
                names = set()
                for r in yara[:10]:
                    rn = r.get("rule_name", "")
                    desc = r.get("description", "")
                    if rn:
                        names.add(rn)
                    if desc:
                        names.add(desc)
                if names:
                    threat_label = ", ".join(list(names)[:3])

        categories = attrs.get("categories")
        cats = []
        if isinstance(categories, dict) and categories:
            for k, v in categories.items():
                desc = f"{v}" if v else k
                cats.append(f"{k}: {desc}")

        if not threat_label and cats and malicious > 0:
            for c in cats:
                low = c.lower()
                if "malicious" in low or "malware" in low or "phishing" in low or "c2" in low or "command" in low:
                    threat_label = c.split(": ", 1)[-1] if ": " in c else c
                    break

        if cats:
            categories_str = ", ".join(cats)

        sig_info = attrs.get("signature_info")
        if isinstance(sig_info, dict):
            family_label = sig_info.get("family")
        if not family_label:
            tags = attrs.get("tags", [])
            if tags:
                family_label = ", ".join(tags[:5])

    ip_details = None
    if ioc_type == "ip":
        parts = []
        country = attrs.get("country")
        as_owner = attrs.get("as_owner")
        net = attrs.get("network")
        if country:
            parts.append(f"Country: {country}")
        if as_owner:
            parts.append(f"AS: {as_owner}")
        if net:
            parts.append(f"Network: {net}")
        if parts:
            ip_details = " | ".join(parts)

    label = ioc_type.upper()
    print(f"[{label}] {value}")
    print(f"  Malicious:  {malicious}")
    print(f"  Suspicious: {suspicious}")
    print(f"  Harmless:   {harmless}")
    print(f"  Undetected: {undetected}")
    print(f"  Result: {result_str}")

    if threat_label:
        print(f"  Popular Threat Label: {threat_label}")
    if categories_str:
        print(f"  Threat Categories: {categories_str}")
    if family_label:
        print(f"  Family Label: {family_label}")
    if ip_details:
        print(f"  IP Details: {ip_details}")
    print()

    return {
        "type": label,
        "value": value,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "result": result_str,
        "popular_threat_label": threat_label or "",
        "threat_categories": categories_str or "",
        "family_label": family_label or "",
        "ip_details": ip_details or "",
        "error": "",
    }


def process_single(item: tuple) -> dict:
    value, ioc_type = item
    try:
        data = check(value, ioc_type)
        return extract_result(value, ioc_type, data)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"type": ioc_type.upper(), "value": value, "error": f"HTTP Error {e.code}: {body}"}
    except urllib.error.URLError as e:
        return {"type": ioc_type.upper(), "value": value, "error": f"Connection error: {e.reason}"}
    except Exception as e:
        return {"type": ioc_type.upper(), "value": value, "error": f"Unexpected error: {e}"}


def write_csv(filepath: str, results: list[dict]):
    fieldnames = [
        "type", "value", "malicious", "suspicious", "harmless", "undetected",
        "result", "popular_threat_label", "threat_categories", "family_label",
        "ip_details", "error",
    ]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def write_json(filepath: str, results: list[dict]):
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)


def write_html(filepath: str, results: list[dict]):
    mc = sum(1 for r in results if "MALICIOUS" in r.get("result", ""))
    sc = sum(1 for r in results if "SUSPICIOUS" in r.get("result", ""))
    cc = sum(1 for r in results if r.get("result") == "CLEAN")
    ec = sum(1 for r in results if r.get("error"))

    rows_html = ""
    for r in results:
        err = r.get("error", "")
        low = r.get("result", "").lower() if not err else ""
        badge = "danger" if "malicious" in low else ("warning" if "suspicious" in low else ("success" if low == "clean" else "secondary"))
        if err:
            badge = "dark"
        row_cells = f"""
            <tr class="row-{badge}">
                <td><span class="type-badge type-{r.get('type', '').lower()}">{r.get("type", "")}</span></td>
                <td class="value-cell">{r.get("value", "")}</td>
                <td class="num {badge}-text">{r.get("malicious", "")}</td>
                <td class="num">{r.get("suspicious", "")}</td>
                <td class="num">{r.get("harmless", "")}</td>
                <td class="num">{r.get("undetected", "")}</td>
                <td>{'' if err else f'<span class="badge badge-{badge}">{r.get("result", "")}</span>'}</td>
                <td class="extra">{r.get("popular_threat_label", "")}</td>
                <td class="extra">{r.get("threat_categories", "")}</td>
                <td class="extra">{r.get("family_label", "")}</td>
                <td class="extra">{r.get("ip_details", "")}</td>
                <td class="err-cell">{err}</td>
            </tr>"""
        rows_html += row_cells

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VirusTotal Scan Report</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: linear-gradient(135deg, #0f1724 0%, #1a2744 100%); min-height: 100vh; padding: 30px 20px; color: #e0e0e0; }}
.container {{ max-width: 1400px; margin: 0 auto; }}
.header {{ text-align: center; padding: 30px 0 20px; }}
.header h1 {{ font-size: 28px; font-weight: 700; background: linear-gradient(90deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 1px; }}
.header p {{ color: #94a3b8; font-size: 14px; margin-top: 6px; }}
.cards {{ display: flex; gap: 14px; flex-wrap: wrap; justify-content: center; margin-bottom: 28px; }}
.card {{ flex: 1; min-width: 120px; max-width: 200px; padding: 18px 14px; border-radius: 12px; text-align: center; backdrop-filter: blur(8px); box-shadow: 0 4px 15px rgba(0,0,0,.3); }}
.card-total {{ background: linear-gradient(135deg, #1e293b, #334155); }}
.card-malicious {{ background: linear-gradient(135deg, #450a0a, #7f1d1d); }}
.card-suspicious {{ background: linear-gradient(135deg, #422006, #713f12); }}
.card-clean {{ background: linear-gradient(135deg, #052e16, #14532d); }}
.card-error {{ background: linear-gradient(135deg, #1f0929, #3b0764); }}
.card .num {{ font-size: 32px; font-weight: 800; display: block; }}
.card .lbl {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; opacity: .8; }}
.num-danger {{ color: #f87171; }} .num-warning {{ color: #fbbf24; }} .num-success {{ color: #4ade80; }} .num-secondary {{ color: #94a3b8; }} .num-dark {{ color: #c084fc; }}
.table-wrap {{ background: rgba(30, 41, 59, .85); border-radius: 14px; overflow-x: auto; box-shadow: 0 8px 32px rgba(0,0,0,.4); backdrop-filter: blur(4px); }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; min-width: 1000px; }}
thead {{ position: sticky; top: 0; z-index: 2; }}
th {{ background: #1e293b; color: #94a3b8; padding: 14px 10px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .8px; border-bottom: 2px solid #334155; white-space: nowrap; }}
td {{ padding: 12px 10px; border-bottom: 1px solid rgba(51,65,85,.5); vertical-align: top; }}
tbody tr {{ transition: background .15s; }}
tbody tr:hover {{ background: rgba(96, 165, 250, .08) !important; }}
.row-danger {{ background: rgba(127, 29, 29, .25); }}
.row-warning {{ background: rgba(113, 63, 18, .2); }}
.row-success {{ background: rgba(20, 83, 45, .15); }}
.row-secondary {{ background: transparent; }}
.row-dark {{ background: rgba(59, 7, 100, .2); }}
.value-cell {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; word-break: break-all; max-width: 260px; color: #e2e8f0; }}
.num {{ font-family: monospace; font-size: 13px; font-weight: 600; text-align: center; color: #cbd5e1; }}
.danger-text {{ color: #f87171 !important; }}
.badge {{ display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: .3px; white-space: nowrap; }}
.badge-danger {{ background: rgba(248, 113, 113, .2); color: #fca5a5; }}
.badge-warning {{ background: rgba(251, 191, 36, .2); color: #fcd34d; }}
.badge-success {{ background: rgba(74, 222, 128, .2); color: #86efac; }}
.badge-secondary {{ background: rgba(148, 163, 184, .15); color: #94a3b8; }}
.badge-dark {{ background: rgba(192, 132, 252, .2); color: #c084fc; }}
.type-badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: .5px; }}
.type-ip {{ background: rgba(59, 130, 246, .25); color: #93c5fd; }}
.type-hash {{ background: rgba(168, 85, 247, .25); color: #c4b5fd; }}
.type-domain {{ background: rgba(34, 197, 94, .25); color: #86efac; }}
.type-url {{ background: rgba(251, 191, 36, .2); color: #fcd34d; }}
.extra {{ color: #94a3b8; font-size: 12px; max-width: 160px; word-break: break-word; }}
.err-cell {{ color: #fca5a5; font-size: 12px; max-width: 160px; word-break: break-word; }}
@media (max-width: 800px) {{ .card {{ min-width: 80px; }} .card .num {{ font-size: 24px; }} }}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>&#9881; VirusTotal Scan Report</h1>
  <p>{len(results)} indicator{'s' if len(results) != 1 else ''} scanned</p>
</div>
<div class="cards">
  <div class="card card-total"><span class="num num-secondary">{len(results)}</span><span class="lbl">Total</span></div>
  <div class="card card-malicious"><span class="num num-danger">{mc}</span><span class="lbl">Malicious</span></div>
  <div class="card card-suspicious"><span class="num num-warning">{sc}</span><span class="lbl">Suspicious</span></div>
  <div class="card card-clean"><span class="num num-success">{cc}</span><span class="lbl">Clean</span></div>
  <div class="card card-error"><span class="num num-dark">{ec}</span><span class="lbl">Errors</span></div>
</div>
<div class="table-wrap">
<table>
<thead><tr>
  <th>Type</th><th>Value</th><th>Malicious</th><th>Suspicious</th><th>Harmless</th>
  <th>Undetected</th><th>Result</th><th>Threat Label</th><th>Categories</th>
  <th>Family</th><th>IP Details</th><th>Error</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>
</div>
</body>
</html>"""
    with open(filepath, "w") as f:
        f.write(html)


def write_pdf(filepath: str, results: list[dict]):
    from fpdf import FPDF

    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()
    pdf.set_margin(10)

    def _resolve_font(fname):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        paths = [
            os.path.join(script_dir, fname),
            os.path.join("/usr/share/fonts/truetype/dejavu", fname),
            os.path.join("/Library/Fonts", fname),
            os.path.expanduser(f"~/Library/Fonts/{fname}"),
            os.path.join("C:\\Windows\\Fonts", fname.replace("DejaVuSans", "DejaVu Sans")),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    sans = _resolve_font("DejaVuSans.ttf")
    bold = _resolve_font("DejaVuSans-Bold.ttf")
    if sans and bold:
        pdf.add_font("DejaVu", "", sans)
        pdf.add_font("DejaVu", "B", bold)
        font_family = "DejaVu"
    else:
        font_family = "Helvetica"

    mc = sum(1 for r in results if "MALICIOUS" in r.get("result", ""))
    sc = sum(1 for r in results if "SUSPICIOUS" in r.get("result", ""))
    cc = sum(1 for r in results if r.get("result") == "CLEAN")
    ec = sum(1 for r in results if r.get("error"))

    pw = 277
    x0 = 10

    pdf.set_fill_color(44, 62, 80)
    pdf.rect(0, 0, 297, 24, "F")
    pdf.set_font(font_family, "B", 18)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(x0, 5)
    pdf.cell(pw, 10, "VirusTotal Scan Report", align="C")
    pdf.set_font(font_family, "", 10)
    pdf.set_text_color(189, 195, 199)
    pdf.set_xy(x0, 15)
    pdf.cell(pw, 6, f"{len(results)} indicator{'s' if len(results) != 1 else ''} scanned", align="C")

    card_colors = [
        ("Total", str(len(results)), 236, 239, 244, 44, 62, 80),
        ("Malicious", str(mc), 252, 228, 228, 198, 40, 40),
        ("Suspicious", str(sc), 255, 243, 205, 245, 127, 23),
        ("Clean", str(cc), 212, 237, 218, 46, 125, 50),
        ("Errors", str(ec), 232, 213, 245, 123, 31, 162),
    ]
    card_y = 30
    card_w = 53
    card_h = 22
    card_gap = (pw - len(card_colors) * card_w) / (len(card_colors) - 1)

    for i, (lbl, val, rb, gb, bb, rt, gt, bt) in enumerate(card_colors):
        cx = x0 + i * (card_w + card_gap)
        pdf.set_fill_color(rb, gb, bb)
        pdf.rect(cx, card_y, card_w, card_h, "DF")
        pdf.set_font(font_family, "B", 20)
        pdf.set_text_color(rt, gt, bt)
        pdf.set_xy(cx, card_y + 2)
        pdf.cell(card_w, 11, val, align="C")
        pdf.set_font(font_family, "", 9)
        pdf.set_xy(cx, card_y + 13)
        pdf.cell(card_w, 7, lbl, align="C")

    table_y = card_y + card_h + 10

    type_bg = {"IP": (59, 130, 246), "HASH": (168, 85, 247),
               "DOMAIN": (34, 197, 94), "URL": (251, 191, 36)}
    type_fg = {"IP": (255, 255, 255), "HASH": (255, 255, 255),
               "DOMAIN": (255, 255, 255), "URL": (0, 0, 0)}

    headers = ["Type", "Value", "Malicious", "Suspicious", "Harmless",
               "Undetected", "Result", "Threat Label", "Categories",
               "Family", "IP Details", "Error"]
    col_w = [16, 48, 14, 14, 14, 14, 26, 26, 26, 24, 24, 27]
    hdr_sum = sum(col_w)
    if hdr_sum < pw:
        col_w[-1] += pw - hdr_sum

    th = 9
    pdf.set_fill_color(52, 73, 94)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(font_family, "B", 8.5)
    pdf.set_xy(x0, table_y)
    for i, h in enumerate(headers):
        pdf.cell(col_w[i], th, h, border=1, fill=True, align="C")

    row_colors = {
        "malicious": (252, 228, 228),
        "suspicious": (255, 243, 205),
        "clean": (212, 237, 218),
        "error": (232, 213, 245),
        "none": (255, 255, 255),
    }
    rh = 9
    cy = table_y + th

    for r in results:
        err = r.get("error", "")
        low = r.get("result", "").lower() if not err else ""
        if err:
            cat = "error"
        elif "malicious" in low:
            cat = "malicious"
        elif "suspicious" in low:
            cat = "suspicious"
        elif low == "clean":
            cat = "clean"
        else:
            cat = "none"

        if cy + rh > 200:
            pdf.add_page(orientation="L")
            cy = 10
            pdf.set_fill_color(52, 73, 94)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font(font_family, "B", 8.5)
            pdf.set_xy(x0, cy)
            for i, h in enumerate(headers):
                pdf.cell(col_w[i], th, h, border=1, fill=True, align="C")
            cy += th

        rtype = r.get("type", "")
        tbg = type_bg.get(rtype, (100, 116, 139))
        tfg = type_fg.get(rtype, (255, 255, 255))

        val_disp = r.get("value", "")
        if len(val_disp) > 30:
            val_disp = val_disp[:27] + "..."

        fb = row_colors[cat]

        pdf.set_fill_color(*tbg)
        pdf.set_text_color(*tfg)
        pdf.set_font(font_family, "B", 7.5)
        pdf.set_xy(x0, cy)
        pdf.cell(col_w[0], rh, rtype[:4], border=1, fill=True, align="C")

        pdf.set_fill_color(*fb)
        pdf.set_text_color(33, 33, 33)
        pdf.set_font(font_family, "", 8)

        cells = [val_disp,
                 str(r.get("malicious", "")), str(r.get("suspicious", "")),
                 str(r.get("harmless", "")), str(r.get("undetected", "")),
                 err if err else r.get("result", ""),
                 r.get("popular_threat_label", "")[:20],
                 r.get("threat_categories", "")[:20],
                 r.get("family_label", "")[:18],
                 r.get("ip_details", "")[:18],
                 err[:20]]
        for i, d in enumerate(cells):
            pdf.cell(col_w[i + 1], rh, d, border=1, fill=True, align="C" if 1 <= i <= 5 else "L")

        cy += rh

    pdf.set_font(font_family, "", 7)
    pdf.set_text_color(130, 130, 130)
    pdf.set_xy(x0, cy + 2)
    pdf.cell(pw, 4, "Generated by VirusTotal Check Tool", align="C")

    pdf.output(filepath)


ALL_FORMATS = ["txt", "csv", "json", "html", "pdf"]


def _parse_format(val: str) -> Union[str, list[str]]:
    if val.lower() == "all":
        return ALL_FORMATS[:]
    if val in ALL_FORMATS:
        return val
    raise argparse.ArgumentTypeError(f"unknown format: {val}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check IP addresses, hashes, domains, or URLs against VirusTotal."
    )
    parser.add_argument("--ip", metavar="IP", help="Single IP address to check.")
    parser.add_argument("--hash", metavar="HASH", help="Single file hash (MD5, SHA-1, SHA-256) to check.")
    parser.add_argument("--domain", metavar="DOMAIN", help="Single domain to check.")
    parser.add_argument("--url", metavar="URL", help="Single URL to check.")
    parser.add_argument("--file", "-f", metavar="FILE", help="File with up to 500 indicators (IP, hash, domain, URL — auto-detected per line).")
    parser.add_argument("--thread", "-t", type=int, choices=THREAD_OPTIONS,
                        default=3, help="Scanning thread speed. low=1, default=3, medium=5, high=8 threads.")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Save output to a file (format controlled by --format).")
    parser.add_argument("--format", type=_parse_format, metavar="{txt,csv,json,pdf,html}",
                        default="txt", help="Output file format: Select 'all' to save in all supported formats. Default: txt.")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if isinstance(args.format, str):
        args.format = [args.format]

    if not args.ip and not args.hash and not args.domain and not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    results = []
    tee = None

    if args.output and "txt" in args.format:
        try:
            tee = Tee(args.output)
            sys.stdout = tee
        except Exception as e:
            print(f"Error: Cannot open output file '{args.output}': {e}")
            sys.exit(1)

    try:
        single = {"ip": args.ip, "hash": args.hash, "domain": args.domain, "url": args.url}
        provided = {k: v for k, v in single.items() if v}

        if provided and args.file:
            print("Error: Provide either a single indicator or --file, not both.")
            sys.exit(1)

        if len(provided) > 1:
            print("Error: Provide only one single indicator.")
            sys.exit(1)

        if args.file:
            try:
                items = read_items_from_file(args.file)
            except FileNotFoundError:
                print(f"Error: File '{args.file}' not found.")
                sys.exit(1)
            except PermissionError:
                print(f"Error: Permission denied to read '{args.file}'.")
                sys.exit(1)
            except Exception as e:
                print(f"Error reading file: {e}")
                sys.exit(1)

            if len(items) > 500:
                print(f"Error: File contains {len(items)} indicators. Maximum allowed is 500.")
                sys.exit(1)
            if len(items) < 1:
                print("Error: File is empty.")
                sys.exit(1)

            typed_items = [(v, detect_type(v)) for v in items]
            num_threads = args.thread

            print(f"Checking {len(items)} indicators from '{args.file}' (threads: {num_threads}):\n")

            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = {executor.submit(process_single, t): t for t in typed_items}
                for future in as_completed(futures):
                    row = future.result()
                    results.append(row)
                    if row.get("error"):
                        print(f"[{row['type']}] {row['value']}")
                        print(f"  Error: {row['error']}\n")
                        if "429" in row["error"] or "QuotaExceeded" in row["error"]:
                            print("Quota exceeded. Stopping further checks and saving partial results.\n")
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
        else:
            ioc_type, value = next(iter(provided.items()))
            try:
                data = check(value, ioc_type)
                row = extract_result(value, ioc_type, data)
                results.append(row)
            except urllib.error.HTTPError as e:
                body = e.read().decode()
                print(f"HTTP Error {e.code}: {body}")
                sys.exit(1)
            except urllib.error.URLError as e:
                print(f"Connection error: {e.reason}")
                sys.exit(1)
            except Exception as e:
                print(f"Unexpected error: {e}")
                sys.exit(1)

        if args.output:
            if "txt" in args.format:
                print(f"Output saved to: {args.output}")
            for fmt in args.format:
                if fmt == "txt":
                    continue
                if len(args.format) == 1:
                    outpath = args.output
                else:
                    outpath = os.path.splitext(args.output)[0] + "." + fmt
                try:
                    if fmt == "csv":
                        write_csv(outpath, results)
                    elif fmt == "json":
                        write_json(outpath, results)
                    elif fmt == "html":
                        write_html(outpath, results)
                    elif fmt == "pdf":
                        write_pdf(outpath, results)
                    print(f"Output saved to: {outpath}")
                except Exception as e:
                    print(f"Error writing {fmt} file: {e}")
                    sys.exit(1)

    finally:
        if tee:
            sys.stdout = tee.stdout
            tee.close()


if __name__ == "__main__":
    main()
