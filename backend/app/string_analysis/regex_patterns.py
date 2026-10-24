URL_PATTERN = r"https?://[^\s\"'<>]+"

IP_PATTERN = (
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

EMAIL_PATTERN = (
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

BASE64_PATTERN = (
    r"(?:[A-Za-z0-9+/]{20,}={0,2})"
)

API_KEY_PATTERN = (
    r"AIza[0-9A-Za-z\-_]{35}"
)

FIREBASE_PATTERN = (
    r"https://.*firebaseio\.com"
)

BITCOIN_PATTERN = (
    r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"
)