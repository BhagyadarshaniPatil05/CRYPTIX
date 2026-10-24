import re

from app.string_analysis.regex_patterns import (
    URL_PATTERN,
    IP_PATTERN,
    EMAIL_PATTERN,
    BASE64_PATTERN,
    API_KEY_PATTERN,
    FIREBASE_PATTERN,
    BITCOIN_PATTERN,
)


def detect_indicators(strings):
    """
    Detect suspicious indicators from extracted strings.
    """

    indicators = {
        "urls": [],
        "ip_addresses": [],
        "emails": [],
        "firebase_urls": [],
        "api_keys": [],
        "base64_strings": [],
        "bitcoin_addresses": [],
    }

    for text in strings:

        if re.search(URL_PATTERN, text):
            indicators["urls"].append(text)

        if re.search(IP_PATTERN, text):
            indicators["ip_addresses"].append(text)

        if re.search(EMAIL_PATTERN, text):
            indicators["emails"].append(text)

        if re.search(FIREBASE_PATTERN, text):
            indicators["firebase_urls"].append(text)

        if re.search(API_KEY_PATTERN, text):
            indicators["api_keys"].append(text)

        if re.search(BASE64_PATTERN, text):
            indicators["base64_strings"].append(text)

        if re.search(BITCOIN_PATTERN, text):
            indicators["bitcoin_addresses"].append(text)

    # Remove duplicates
    for key in indicators:
        indicators[key] = sorted(list(set(indicators[key])))

    return indicators