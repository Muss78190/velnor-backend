from datetime import datetime
import os
from typing import Dict, List
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image
)

# ---------- Date FR ----------
months_fr = [
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre"
]
now = datetime.now()
date_fr = f"{now.day} {months_fr[now.month - 1]} {now.year}"

# ---------- Couleurs & Styles ----------
BLU = colors.HexColor("#0C1C60")
LIGHT_BG = colors.HexColor("#F6F8FC")
GREY_TEXT = colors.HexColor("#555555")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CustomTitle", fontSize=24, textColor=BLU, leading=28, spaceAfter=6))
styles.add(ParagraphStyle(name="CustomSubtitle", fontSize=18, textColor=BLU, leading=22, spaceAfter=12))
styles.add(ParagraphStyle(name="CustomBody", fontSize=11, textColor=GREY_TEXT, leading=15))
styles.add(ParagraphStyle(name="CustomBullet", fontSize=11, textColor=GREY_TEXT, leading=16, leftIndent=10))
styles.add(ParagraphStyle(name="CustomFooter", fontSize=9, textColor=colors.grey, alignment=1))

# ---------- Badge score dynamique ----------
def get_score_badge(score: int) -> str:
    if score < 40:
        return "🔴 Niveau critique – À corriger d'urgence."
    elif score < 70:
        return "🟠 Niveau moyen – Sécurité partielle, des corrections sont nécessaires."
    elif score < 90:
        return "🟡 Niveau correct – Quelques recommandations à appliquer."
    else:
        return "🟢 Sécurité optimale – Aucun risque majeur détecté."

# ---------- Génération du PDF ----------
def generate_pdf_report(data: Dict, filename: str) -> str:
    output_dir = os.path.join(os.path.dirname(__file__), "rapports")
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm,
                            topMargin=25 * mm, bottomMargin=25 * mm)
    flow: List = []

    # ---------- Logo (optionnel) ----------
    logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=32, height=32)
        logo.hAlign = 'LEFT'
        flow.append(logo)

    # ---------- Titre principal ----------
    flow.append(Paragraph("Velnor", styles["CustomTitle"]))
    flow.append(Paragraph("Audit de sécurité", styles["CustomSubtitle"]))
    flow.append(Spacer(1, 6))
    flow.append(Paragraph(data["url"], styles["CustomBody"]))
    flow.append(Paragraph(date_fr, styles["CustomBody"]))
    flow.append(Spacer(1, 12))

    # ---------- Bloc Score + Résumé + Badge ----------
    score_value = data.get("score", 0)
    badge_msg = get_score_badge(score_value)

    score_display = Paragraph(f'<font size=16 color="#0C1C60"><b>{score_value}/100</b></font>', styles["CustomBody"])
    resume_box = Paragraph(data.get("resume", ""), styles["CustomBody"])
    badge_para = Paragraph(badge_msg, styles["CustomBody"])

    table_data = [
        [Paragraph("<b>Score</b>", styles["CustomBody"]),
         Paragraph("<b>Résumé</b>", styles["CustomBody"])],
        [score_display, resume_box],
        ["", badge_para]
    ]
    score_table = Table(table_data, colWidths=[60 * mm, None])
    score_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 1), (-1, 1), LIGHT_BG),
        ("SPAN", (1, 2), (1, 2)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    flow.append(score_table)
    flow.append(Spacer(1, 14))

    # ---------- Failles détectées ----------
    flow.append(Paragraph("Failles détectées", styles["CustomSubtitle"]))
    anomalies = data.get("anomalies", [])
    if anomalies:
        for line in anomalies:
            flow.append(Paragraph(line, styles["CustomBullet"]))
    else:
        flow.append(Paragraph("Aucune faille critique détectée.", styles["CustomBody"]))
    flow.append(Spacer(1, 12))

    # ---------- Recommandations (2 colonnes) ----------
    flow.append(Paragraph("Recommandations", styles["CustomSubtitle"]))
    recommendations = data.get("recommendations", [])
    if recommendations:
        mid = len(recommendations) // 2 + len(recommendations) % 2
        left_col = [Paragraph(r, styles["CustomBullet"]) for r in recommendations[:mid]]
        right_col = [Paragraph(r, styles["CustomBullet"]) for r in recommendations[mid:]]

        rec_table = Table([[left_col, right_col]], colWidths=[None, None])
        rec_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        flow.append(rec_table)
    else:
        flow.append(Paragraph("Aucune recommandation pour ce site.", styles["CustomBody"]))
    flow.append(Spacer(1, 20))

    # ---------- Footer ----------
    flow.append(HRFlowable(width="100%", color=colors.grey))
    flow.append(Paragraph("Audit réalisé automatiquement par l’IA Velnor APE-X™", styles["CustomFooter"]))

    # Génération finale
    doc.build(flow)
    return path
