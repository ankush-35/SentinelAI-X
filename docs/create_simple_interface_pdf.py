"""Create a short PDF explanation for SentinelAI-X interface discovery."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_FILE = ROOT / "docs" / "interface_discovery_simple_explanation.pdf"


def build_pdf() -> None:
    """Build a compact PDF with simple Hinglish explanations."""
    styles = getSampleStyleSheet()
    title = styles["Title"]
    heading = styles["Heading2"]
    body = ParagraphStyle(
        "SimpleBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        spaceAfter=8,
    )

    doc = SimpleDocTemplate(
        str(OUTPUT_FILE),
        pagesize=A4,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )

    story = [
        Paragraph("SentinelAI-X: Interface Discovery Simple Explanation", title),
        Spacer(1, 10),
        Paragraph("Module Purpose", heading),
        Paragraph(
            "interface_discovery.py ka kaam system ke available network "
            "interfaces ko detect karna hai. Ye module packet_capture.py se "
            "pehle use hoga, taaki user ko pata chale kaunsi interface par "
            "traffic capture karna hai.",
            body,
        ),
        Paragraph("Main Imports", heading),
        Paragraph(
            "argparse CLI arguments ke liye, logging structured logs ke liye, "
            "dataclass clean data model ke liye, aur scapy.all.IFACES network "
            "interfaces read karne ke liye use hota hai.",
            body,
        ),
        Paragraph("NetworkInterface Class", heading),
        Paragraph(
            "Ye dataclass ek interface ka normalized data store karti hai: "
            "name, description, index, mac_address, aur ip_address. frozen=True "
            "data ko immutable banata hai, slots=True memory efficient banata hai.",
            body,
        ),
        Paragraph("JsonLogFormatter Class", heading),
        Paragraph(
            "Ye logs ko JSON format me convert karta hai. Cybersecurity tools me "
            "structured logs useful hote hain kyunki SIEM ya log analyzers easily "
            "parse kar sakte hain.",
            body,
        ),
        Paragraph("configure_logging() Function", heading),
        Paragraph(
            "Ye root logger setup karta hai aur JsonLogFormatter attach karta hai. "
            "User --log-level se DEBUG, INFO, ERROR jaise levels choose kar sakta hai.",
            body,
        ),
        Paragraph("InterfaceDiscovery Class", heading),
        Paragraph(
            "Ye reusable main class hai. Future packet capture modules direct Scapy "
            "use karne ke bajay is class se clean NetworkInterface objects le sakte hain.",
            body,
        ),
        Paragraph("discover() Function", heading),
        Paragraph(
            "Ye IFACES.values() se raw Scapy interfaces leta hai, har interface ko "
            "_normalize_interface() se clean format me convert karta hai, aur list "
            "return karta hai. Error aane par InterfaceDiscoveryError raise hoti hai.",
            body,
        ),
        Paragraph("get_interface_by_name() Function", heading),
        Paragraph(
            "Ye function interface name se specific interface search karta hai. "
            "casefold() use hota hai taaki comparison case-insensitive ho.",
            body,
        ),
        Paragraph("render_table() Function", heading),
        Paragraph(
            "Ye discovered interfaces ko readable table me print karta hai. Missing "
            "MAC/IP/index ke liye N/A show hota hai.",
            body,
        ),
        Paragraph("Helper Functions", heading),
        Paragraph(
            "_safe_string(), _safe_optional_string(), aur _safe_int() raw Scapy "
            "attributes ko safely read karte hain. _extract_ip_address() platform "
            "differences handle karta hai, kyunki Scapy IP info kabhi ip aur kabhi "
            "ips attribute me de sakta hai.",
            body,
        ),
        Paragraph("main() Flow", heading),
        Paragraph(
            "main() CLI args parse karta hai, logging configure karta hai, "
            "InterfaceDiscovery object banata hai, interfaces discover karta hai, "
            "aur final table print karta hai. Success par 0 aur failure par 1 return hota hai.",
            body,
        ),
        Paragraph("Architecture Use", heading),
        Paragraph(
            "Sensor Module flow: interface_discovery.py pehle interface choose karne "
            "me help karega. Uske baad packet_capture.py selected interface par packets "
            "capture karega, packet_parser.py parse karega, traffic_logger.py store karega, "
            "aur feature_extractor.py ML/security features nikalega.",
            body,
        ),
        Paragraph("Run Command", heading),
        Paragraph(
            "python sensor/interface_discovery.py --log-level INFO",
            body,
        ),
    ]

    doc.build(story)


if __name__ == "__main__":
    build_pdf()
