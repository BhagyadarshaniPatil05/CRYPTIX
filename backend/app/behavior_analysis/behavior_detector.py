from app.behavior_analysis.suspicious_apis import SUSPICIOUS_APIS


def detect_behaviors(strings):
    """
    Detect suspicious APIs and behaviors from extracted strings.
    """

    findings = []

    for string in strings:

        for api in SUSPICIOUS_APIS:

            if api in string:

                findings.append({

                    "api": api,
                    "severity": SUSPICIOUS_APIS[api]["severity"],
                    "reason": SUSPICIOUS_APIS[api]["reason"]

                })

    # Remove duplicates
    unique = []

    seen = set()

    for finding in findings:

        key = finding["api"]

        if key not in seen:

            seen.add(key)

            unique.append(finding)

    return unique