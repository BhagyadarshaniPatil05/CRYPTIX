from io import BytesIO

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)


def generate_pdf_report(report: dict):
    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    content = []

    # --------------------------------
    # Title
    # --------------------------------
    content.append(
        Paragraph(
            "CRYPTIX Security Analysis Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    # --------------------------------
    # Executive Summary
    # --------------------------------
    summary = report["executive_summary"]

    content.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    content.append(
        Paragraph(
            f"Package Name: {summary['package_name']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"App Name: {summary['app_name']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Score: {summary['risk_score']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Level: {summary['risk_level']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Threat Level: {summary['threat_level']}",
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 20))

    # --------------------------------
    # Permissions
    # --------------------------------
    content.append(
        Paragraph(
            "Dangerous Permissions",
            styles["Heading1"]
        )
    )

    for permission in report["permissions_analysis"]:

        content.append(
            Paragraph(
                f"""
                • {permission['permission']}
                ({permission['severity']})
                <br/>
                {permission['reason']}
                """,
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 20))

    # --------------------------------
    # Behaviors
    # --------------------------------
    content.append(
        Paragraph(
            "Behavior Analysis",
            styles["Heading1"]
        )
    )

    behaviors = report["behavior_analysis"]

    if not behaviors:
        content.append(
            Paragraph(
                "No suspicious behavior detected.",
                styles["BodyText"]
            )
        )

    else:
        for behavior in behaviors:

            content.append(
                Paragraph(
                    f"""
                    • {behavior['api']}
                    ({behavior['severity']})
                    <br/>
                    {behavior['reason']}
                    """,
                    styles["BodyText"]
                )
            )

    content.append(PageBreak())

    # --------------------------------
    # Threat Assessment
    # --------------------------------
    threat = report["threat_assessment"]

    content.append(
        Paragraph(
            "Threat Assessment",
            styles["Heading1"]
        )
    )

    content.append(
        Paragraph(
            threat["summary"],
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "Key Findings",
            styles["Heading2"]
        )
    )

    for finding in threat["key_findings"]:

        content.append(
            Paragraph(
                f"• {finding}",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "Recommendations",
            styles["Heading2"]
        )
    )

    for recommendation in threat["recommended_actions"]:

        content.append(
            Paragraph(
                f"• {recommendation}",
                styles["BodyText"]
            )
        )

    doc.build(content)

    buffer.seek(0)

    return buffer