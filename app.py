from flask import Flask, render_template, send_file
from database import get_security_data

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

import os


# ============================================================
# CREATE FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    # Get security information
    data = get_security_data()

    # Send data to dashboard.html
    return render_template(
        "dashboard.html",
        data=data
    )


# ============================================================
# PDF REPORT
# ============================================================

@app.route("/download_report")
def download_report():

    # Get security information
    data = get_security_data()

    # Create reports folder
    os.makedirs("reports", exist_ok=True)

    # PDF location
    pdf_path = os.path.join(
        "reports",
        "endpoint_security_report.pdf"
    )

    # Create PDF document
    document = SimpleDocTemplate(
        pdf_path,
        pagesize=A4
    )

    # Get default styles
    styles = getSampleStyleSheet()

    # Store PDF elements
    elements = []


    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "ENDPOINT SECURITY REPORT",
            styles["Title"]
        )
    )

    elements.append(
        Spacer(1, 0.3 * inch)
    )


    # --------------------------------------------------------
    # SECURITY SUMMARY
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            f"<b>Risk Score:</b> {data['risk_score']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Risk Level:</b> {data['risk_level']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Total Threats:</b> {data['total_threats']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Network Alerts:</b> {data['network_alerts']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Suspicious Processes:</b> "
            f"{data['suspicious_processes']}",
            styles["Normal"]
        )
    )

    elements.append(
        Spacer(1, 0.3 * inch)
    )


    # --------------------------------------------------------
    # ALERTS
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "Detected Security Alerts",
            styles["Heading2"]
        )
    )

    elements.append(
        Spacer(1, 0.1 * inch)
    )


    # Table header
    table_data = [
        [
            "Type",
            "Description",
            "Name",
            "Risk"
        ]
    ]


    # Add alerts
    for alert in data["alerts"]:

        table_data.append(
            [
                alert["type"],
                alert["description"],
                alert["name"],
                alert["risk"]
            ]
        )


    # Create table
    table = Table(
        table_data,
        repeatRows=1
    )


    # Table design
    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.darkblue
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    1,
                    colors.black
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ]
        )
    )


    elements.append(table)


    # --------------------------------------------------------
    # GENERATE PDF
    # --------------------------------------------------------

    document.build(elements)


    # Send PDF to browser
    return send_file(
        pdf_path,
        as_attachment=True
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )