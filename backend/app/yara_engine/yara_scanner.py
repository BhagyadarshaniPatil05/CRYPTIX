import yara
import logging
from pathlib import Path

logger = logging.getLogger("cryptix.yara")


def scan_with_yara(apk_path: str):
    """
    Scan an APK using all YARA rules in rules/ directory.
    """
    rules_dir = Path(__file__).parent / "rules"

    if not rules_dir.exists():
        logger.warning("YARA rules directory does not exist.")
        return []

    rule_files = {}
    for file in rules_dir.glob("*.yar"):
        rule_files[file.stem] = str(file)

    if not rule_files:
        logger.warning("No YARA rule (.yar) files found.")
        return []

    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(apk_path)
    except Exception as e:
        logger.error(f"YARA compilation or scanning error for {apk_path}: {str(e)}")
        return []

    findings = []

    for match in matches:
        severity = "Low"

        # Read severity from rule metadata if available
        try:
            severity = match.meta.get("severity", "Low")
        except Exception:
            pass

        findings.append({
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": match.tags,
            "severity": severity
        })

    return findings