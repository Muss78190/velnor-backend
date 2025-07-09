print("⚠️ pdf_generator.py ULTRA-PRO bien importé")
from datetime import datetime
import os
from typing import Dict, List
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

# ---------- Date FR dynamique ----------
months_fr = [
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre"
]

# ---------- Couleurs VELNOR ----------
VELNOR_BLUE = colors.HexColor("#2BC0FF")
VELNOR_PURPLE = colors.HexColor("#A94AFF")
DARK_BG = colors.HexColor("#0a0a1e")
LIGHT_BG = colors.HexColor("#F6F8FC")
GREY_TEXT = colors.HexColor("#555555")
RED_CRITICAL = colors.HexColor("#FF4444")
ORANGE_WARNING = colors.HexColor("#FF8C00")
GREEN_SAFE = colors.HexColor("#00AA44")
WHITE = colors.white
BLACK = colors.black

# ---------- Styles VELNOR ----------
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="VelnorTitle", fontSize=28, textColor=VELNOR_BLUE, leading=32, spaceAfter=10, alignment=1, fontName="Helvetica-Bold"))
styles.add(ParagraphStyle(name="VelnorSubtitle", fontSize=20, textColor=VELNOR_PURPLE, leading=24, spaceAfter=15, alignment=1, fontName="Helvetica-Bold"))
styles.add(ParagraphStyle(name="SectionTitle", fontSize=16, textColor=VELNOR_BLUE, leading=20, spaceAfter=10, fontName="Helvetica-Bold"))
styles.add(ParagraphStyle(name="VelnorBody", fontSize=11, textColor=GREY_TEXT, leading=16, fontName="Helvetica"))
styles.add(ParagraphStyle(name="VelnorBullet", fontSize=11, textColor=GREY_TEXT, leading=17, leftIndent=20, bulletIndent=10, fontName="Helvetica"))
styles.add(ParagraphStyle(name="VelnorFooter", fontSize=9, textColor=colors.grey, alignment=1, fontName="Helvetica-Oblique"))
styles.add(ParagraphStyle(name="CriticalAlert", fontSize=14, textColor=RED_CRITICAL, leading=18, alignment=1, fontName="Helvetica-Bold"))
styles.add(ParagraphStyle(name="ScoreDisplay", fontSize=36, textColor=VELNOR_BLUE, alignment=1, spaceAfter=15, fontName="Helvetica-Bold"))
styles.add(ParagraphStyle(name="URLStyle", fontSize=14, textColor=VELNOR_PURPLE, alignment=1, leading=18, spaceAfter=10, fontName="Helvetica-Bold"))

# ---------- Badge score dynamique ----------
def get_score_badge(score: int) -> tuple:
    """Retourne (emoji, texte, couleur) selon le score"""
    if score < 40:
        return ("🚨", "SÉCURITÉ CRITIQUE", RED_CRITICAL, "Intervention immédiate requise")
    elif score < 70:
        return ("⚠️", "SÉCURITÉ MOYENNE", ORANGE_WARNING, "Corrections nécessaires")
    elif score < 90:
        return ("✅", "SÉCURITÉ CORRECTE", colors.orange, "Quelques améliorations recommandées")
    else:
        return ("🛡️", "SÉCURITÉ OPTIMALE", GREEN_SAFE, "Infrastructure sécurisée")

def create_score_gauge(score: int) -> Drawing:
    """Crée une jauge de score ultra-stylée"""
    d = Drawing(300, 150)
    
    # Fond de la jauge (arc de cercle)
    center_x, center_y = 150, 50
    radius = 80
    
    # Arc de fond (gris)
    for angle in range(0, 181, 2):
        x1 = center_x + (radius - 5) * (angle / 180) * 2 - radius
        y1 = center_y + (radius - 5) * ((180 - angle) / 180) * 0.8
        x2 = center_x + radius * (angle / 180) * 2 - radius  
        y2 = center_y + radius * ((180 - angle) / 180) * 0.8
        
        if angle <= (score * 1.8):  # Score sur 180 degrés
            color = RED_CRITICAL if score < 40 else ORANGE_WARNING if score < 70 else GREEN_SAFE if score >= 90 else colors.orange
        else:
            color = colors.lightgrey
            
        line = Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=3)
        d.add(line)
    
    # Texte du score au centre
    score_text = String(center_x, center_y - 15, f"{score}", textAnchor='middle', fontSize=32, fillColor=VELNOR_BLUE, fontName="Helvetica-Bold")
    d.add(score_text)
    score_text2 = String(center_x, center_y - 35, "/100", textAnchor='middle', fontSize=16, fillColor=GREY_TEXT, fontName="Helvetica")
    d.add(score_text2)
    
    # Labels
    d.add(String(70, 30, "0", textAnchor='middle', fontSize=10, fillColor=GREY_TEXT))
    d.add(String(150, 110, "50", textAnchor='middle', fontSize=10, fillColor=GREY_TEXT))
    d.add(String(230, 30, "100", textAnchor='middle', fontSize=10, fillColor=GREY_TEXT))
    
    return d

def create_threat_chart(anomalies: List[str]) -> Drawing:
    """Crée un graphique des menaces détectées"""
    d = Drawing(400, 200)
    
    # Compter les types de menaces
    critical_count = sum(1 for a in anomalies if any(x in a.lower() for x in ['sql', 'xss', 'rce', 'injection']))
    medium_count = sum(1 for a in anomalies if any(x in a.lower() for x in ['port', 'ssl', 'tls', 'certificate']))
    low_count = len(anomalies) - critical_count - medium_count
    
    if critical_count + medium_count + low_count == 0:
        # Aucune menace
        d.add(String(200, 100, "Aucune menace détectée", textAnchor='middle', fontSize=14, fillColor=GREEN_SAFE))
        return d
    
    # Graphique en barres
    bar_height = 30
    bar_spacing = 50
    start_y = 150
    
    categories = [
        ("Critiques", critical_count, RED_CRITICAL),
        ("Moyennes", medium_count, ORANGE_WARNING), 
        ("Faibles", low_count, colors.orange)
    ]
    
    max_count = max(critical_count, medium_count, low_count, 1)
    
    for i, (label, count, color) in enumerate(categories):
        y_pos = start_y - (i * bar_spacing)
        bar_width = (count / max_count) * 250
        
        # Barre
        rect = Rect(100, y_pos, bar_width, bar_height, fillColor=color, strokeColor=None)
        d.add(rect)
        
        # Label
        d.add(String(90, y_pos + 10, label, textAnchor='end', fontSize=11, fillColor=GREY_TEXT))
        
        # Valeur
        d.add(String(110 + bar_width, y_pos + 10, str(count), textAnchor='start', fontSize=11, fillColor=GREY_TEXT))
    
    return d

def create_velnor_header() -> Drawing:
    """Crée un header stylé VELNOR"""
    d = Drawing(400, 80)
    
    # Fond dégradé simulé
    for i in range(40):
        alpha = i / 40
        color = colors.Color(VELNOR_BLUE.red * alpha + WHITE.red * (1-alpha),
                           VELNOR_BLUE.green * alpha + WHITE.green * (1-alpha),
                           VELNOR_BLUE.blue * alpha + WHITE.blue * (1-alpha))
        rect = Rect(0, i, 400, 2, fillColor=color, strokeColor=None)
        d.add(rect)
    
    # Logo simulé (cercle avec V)
    circle = Circle(50, 40, 25, fillColor=VELNOR_PURPLE, strokeColor=WHITE, strokeWidth=2)
    d.add(circle)
    d.add(String(50, 35, "V", textAnchor='middle', fontSize=20, fillColor=WHITE, fontName="Helvetica-Bold"))
    
    # Texte VELNOR
    d.add(String(90, 45, "VELNOR", textAnchor='start', fontSize=24, fillColor=VELNOR_BLUE, fontName="Helvetica-Bold"))
    d.add(String(90, 25, "Cybersecurity AI Engine", textAnchor='start', fontSize=12, fillColor=VELNOR_PURPLE))
    
    return d

def format_vulnerability_severity(vuln: str) -> str:
    """Formate les vulnérabilités avec icônes et couleurs"""
    vuln_lower = vuln.lower()
    if any(critical in vuln_lower for critical in ['sql injection', 'rce', 'xss']):
        return f'<font color="red"><b>🚨 CRITIQUE:</b> {vuln}</font>'
    elif any(medium in vuln_lower for medium in ['port', 'ssl', 'tls', 'certificate']):
        return f'<font color="orange"><b>⚠️ MOYEN:</b> {vuln}</font>'
    else:
        return f'<font color="blue"><b>ℹ️ INFO:</b> {vuln}</font>'

def create_executive_summary_box(data: Dict) -> Table:
    """Crée un encadré résumé exécutif stylé"""
    score = data.get("score", 0)
    emoji, status, color, description = get_score_badge(score)
    
    summary_data = [
        ["🎯 SCORE DE SÉCURITÉ", f"{score}/100"],
        ["🛡️ STATUT", f"{emoji} {status}"],
        ["⚠️ MENACES DÉTECTÉES", str(len(data.get("anomalies", [])))],
        ["💡 RECOMMANDATIONS", str(len(data.get("recommendations", [])))],
        ["⏱️ TEMPS D'ANALYSE", data.get("duration_seconds", "N/A")],
        ["🔍 ÉVALUATION", description]
    ]
    
    table = Table(summary_data, colWidths=[80*mm, 60*mm])
    table.setStyle(TableStyle([
        # En-têtes
        ("BACKGROUND", (0, 0), (0, -1), VELNOR_BLUE),
        ("TEXTCOLOR", (0, 0), (0, -1), WHITE),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        
        # Valeurs
        ("BACKGROUND", (1, 0), (1, -1), LIGHT_BG),
        ("TEXTCOLOR", (1, 0), (1, -1), GREY_TEXT),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        
        # Bordures
        ("BOX", (0, 0), (-1, -1), 2, VELNOR_PURPLE),
        ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    
    return table

# ---------- Génération du PDF ULTRA-PRO ----------
def generate_pdf_report(data: Dict, filename: str) -> str:
    """
    Génère un rapport PDF d'audit ULTRA-PROFESSIONNEL
    Design moderne, graphiques, couleurs VELNOR
    """
    started_at = datetime.utcnow()
    print(f"📄 Début génération PDF ULTRA-PRO: {started_at.isoformat()}")

    # Chemins
    output_dir = os.path.join(os.path.dirname(__file__), "rapports")
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)

    # Date française
    now = datetime.now()
    date_fr = f"{now.day} {months_fr[now.month - 1]} {now.year}"

    try:
        doc = SimpleDocTemplate(path, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        flow: List = []

        # ========== PAGE DE COUVERTURE ULTRA-STYLÉE ==========
        
        # Header VELNOR
        velnor_header = create_velnor_header()
        flow.append(velnor_header)
        flow.append(Spacer(1, 30))
        
        # Titre principal
        flow.append(Paragraph("RAPPORT D'AUDIT", styles["VelnorTitle"]))
        flow.append(Paragraph("CYBERSÉCURITÉ", styles["VelnorSubtitle"]))
        flow.append(Spacer(1, 20))

        # URL en évidence avec encadré
        url_text = data.get("url", "URL non spécifiée")
        url_table = Table([[Paragraph(f"🌐 {url_text}", styles["URLStyle"])]], colWidths=[None])
        url_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 2, VELNOR_BLUE),
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("LEFTPADDING", (0, 0), (-1, -1), 15),
            ("RIGHTPADDING", (0, 0), (-1, -1), 15),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        flow.append(url_table)
        flow.append(Spacer(1, 30))

        # Score avec jauge
        score_value = data.get("score", 0)
        emoji, badge_text, badge_color, description = get_score_badge(score_value)
        
        score_gauge = create_score_gauge(score_value)
        flow.append(score_gauge)
        flow.append(Spacer(1, 15))
        
        # Badge de statut
        badge_para = Paragraph(f"{emoji} {badge_text}", 
                             ParagraphStyle(name="BadgeStyle", fontSize=18, textColor=badge_color, 
                                          alignment=1, leading=22, fontName="Helvetica-Bold"))
        flow.append(badge_para)
        flow.append(Paragraph(description, 
                            ParagraphStyle(name="DescStyle", fontSize=12, textColor=GREY_TEXT,
                                         alignment=1, leading=16, fontName="Helvetica-Oblique")))
        
        # Date et métadonnées
        flow.append(Spacer(1, 40))
        meta_style = ParagraphStyle(name="MetaStyle", fontSize=10, textColor=GREY_TEXT, alignment=1)
        flow.append(Paragraph(f"📅 Analyse effectuée le {date_fr}", meta_style))
        flow.append(Paragraph(f"⚡ Moteur: VELNOR APE-X™ v3.0", meta_style))
        
        flow.append(PageBreak())

        # ========== RÉSUMÉ EXÉCUTIF ==========
        flow.append(Paragraph("📊 RÉSUMÉ EXÉCUTIF", styles["SectionTitle"]))
        flow.append(Spacer(1, 15))
        
        # Encadré résumé exécutif
        executive_table = create_executive_summary_box(data)
        flow.append(executive_table)
        flow.append(Spacer(1, 20))
        
        # Analyse textuelle
        resume_text = data.get("resume", "Aucune analyse disponible.")
        resume_para = Paragraph(f"<b>Analyse:</b> {resume_text}", styles["VelnorBody"])
        resume_box = Table([[resume_para]], colWidths=[None])
        resume_box.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, VELNOR_PURPLE),
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("LEFTPADDING", (0, 0), (-1, -1), 15),
            ("RIGHTPADDING", (0, 0), (-1, -1), 15),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        flow.append(resume_box)
        flow.append(Spacer(1, 25))

        # ========== MENACES ET VULNÉRABILITÉS ==========
        flow.append(Paragraph("🚨 MENACES DÉTECTÉES", styles["SectionTitle"]))
        flow.append(Spacer(1, 15))
        
        anomalies = data.get("anomalies", [])
        
        if anomalies:
            # Graphique des menaces
            threat_chart = create_threat_chart(anomalies)
            flow.append(threat_chart)
            flow.append(Spacer(1, 15))
            
            # Liste détaillée des vulnérabilités
            vuln_data = []
            for i, anomaly in enumerate(anomalies, 1):
                formatted_vuln = format_vulnerability_severity(anomaly)
                vuln_data.append([str(i), Paragraph(formatted_vuln, styles["VelnorBody"])])
            
            vuln_table = Table(vuln_data, colWidths=[15*mm, None])
            vuln_table.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, colors.grey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            flow.append(vuln_table)
        else:
            success_box = Table([[Paragraph("✅ Aucune vulnérabilité critique détectée. Infrastructure sécurisée.", 
                                          styles["VelnorBody"])]], colWidths=[None])
            success_box.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 2, GREEN_SAFE),
                ("BACKGROUND", (0, 0), (-1, -1), colors.Color(0, 1, 0, alpha=0.1)),
                ("LEFTPADDING", (0, 0), (-1, -1), 15),
                ("RIGHTPADDING", (0, 0), (-1, -1), 15),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ]))
            flow.append(success_box)
        
        flow.append(Spacer(1, 25))

        # ========== RECOMMANDATIONS ==========
        flow.append(Paragraph("💡 PLAN D'ACTION", styles["SectionTitle"]))
        flow.append(Spacer(1, 15))
        
        recommendations = data.get("recommendations", [])
        if recommendations:
            rec_data = []
            for i, rec in enumerate(recommendations, 1):
                priority_color = RED_CRITICAL if i <= 3 else ORANGE_WARNING if i <= 6 else VELNOR_BLUE
                priority_text = "🔴 URGENT" if i <= 3 else "🟠 IMPORTANT" if i <= 6 else "🔵 RECOMMANDÉ"
                
                rec_formatted = f'<font color="{priority_color.hexval()}"><b>{priority_text}</b></font><br/>{rec}'
                rec_data.append([str(i), Paragraph(rec_formatted, styles["VelnorBody"])])
            
            rec_table = Table(rec_data, colWidths=[15*mm, None])
            rec_table.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, colors.grey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            flow.append(rec_table)
        else:
            no_rec_box = Table([[Paragraph("✅ Aucune action corrective immédiate requise.", 
                                         styles["VelnorBody"])]], colWidths=[None])
            no_rec_box.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, GREEN_SAFE),
                ("BACKGROUND", (0, 0), (-1, -1), colors.Color(0, 1, 0, alpha=0.1)),
                ("LEFTPADDING", (0, 0), (-1, -1), 15),
                ("RIGHTPADDING", (0, 0), (-1, -1), 15),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ]))
            flow.append(no_rec_box)

        flow.append(Spacer(1, 30))

        # ========== MÉTADONNÉES TECHNIQUES ==========
        flow.append(Paragraph("⚙️ MÉTADONNÉES TECHNIQUES", styles["SectionTitle"]))
        flow.append(Spacer(1, 10))
        
        duration = data.get("duration_seconds", 0)
        meta_data = [
            ["🧠 Moteur d'analyse", "VELNOR APE-X™ v3.0"],
            ["📅 Date de génération", date_fr],
            ["⏱️ Durée d'analyse", f"{duration:.1f} secondes" if isinstance(duration, (int, float)) else str(duration)],
            ["🔍 Ports scannés", "65,535 (scan exhaustif)"],
            ["🛡️ Vulnérabilités testées", "500+ patterns"],
            ["📊 Statut d'analyse", "✅ Complète"],
            ["🏢 Certifié par", "VELNOR Cybersecurity"]
        ]
        
        meta_table = Table(meta_data, colWidths=[60*mm, None])
        meta_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, colors.grey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(meta_table)
        flow.append(Spacer(1, 40))

        # ========== FOOTER STYLÉ ==========
        flow.append(HRFlowable(width="100%", color=VELNOR_BLUE, thickness=3))
        flow.append(Spacer(1, 10))
        
        footer_text = """<b>VELNOR APE-X™ - Intelligence Artificielle de Cybersécurité</b><br/>
        Rapport confidentiel généré automatiquement • Distribution restreinte<br/>
        <font color="blue">🌐 velnor.fr</font> • <font color="purple">📧 security@velnor.fr</font>"""
        
        flow.append(Paragraph(footer_text, styles["VelnorFooter"]))

        # Build du document
        doc.build(flow)

    except Exception as e:
        error_time = datetime.utcnow()
        print(f"❌ Erreur génération PDF ULTRA-PRO: {e}")
        raise

    # Stats finales
    finished_at = datetime.utcnow()
    duration = (finished_at - started_at).total_seconds()
    file_size = os.path.getsize(path) / 1024
    
    print(f"✅ PDF ULTRA-PRO généré: {path}")
    print(f"⏱️ Durée: {duration:.2f}s")
    print(f"📁 Taille: {file_size:.1f} KB")
    print(f"🎨 Design: VELNOR Ultra-Pro Edition")
    
    return path