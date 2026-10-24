from app.reporting.report_service import (
    generate_apk_report
)

from app.reporting.report_pdf_generator import (
    generate_pdf_report
)


def generate_apk_pdf(
    db,
    apk_id
):
    report = generate_apk_report(
        db,
        apk_id
    )

    if not report:
        return None

    return generate_pdf_report(
        report
    )