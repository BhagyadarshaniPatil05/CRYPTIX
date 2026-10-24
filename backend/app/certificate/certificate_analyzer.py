import hashlib
from androguard.misc import AnalyzeAPK


def analyze_certificate(apk_path: str):
    """
    Extract certificate information and SHA-256/SHA-1 fingerprints from an APK using Androguard.
    """

    try:
        apk, _, _ = AnalyzeAPK(apk_path)

        certificates = apk.get_certificates()

        if not certificates:
            return {
                "status": "SUCCESS",
                "certificate_count": 0,
                "certificates": []
            }

        certificate_list = []

        for cert in certificates:
            sha256_fp = ""
            sha1_fp = ""

            # Attempt to extract raw DER bytes for SHA-256/SHA-1 fingerprinting
            try:
                raw_bytes = None
                if hasattr(cert, "raw_bytes") and cert.raw_bytes:
                    raw_bytes = cert.raw_bytes
                elif hasattr(cert, "dump"):
                    raw_bytes = cert.dump()

                if raw_bytes:
                    sha256_fp = hashlib.sha256(raw_bytes).hexdigest()
                    sha1_fp = hashlib.sha1(raw_bytes).hexdigest()
                elif hasattr(cert, "sha256_fingerprint"):
                    sha256_fp = cert.sha256_fingerprint.replace(":", "").lower()
            except Exception:
                pass

            cert_data = {
                "issuer": getattr(cert.issuer, "human_friendly", str(cert.issuer)),
                "subject": getattr(cert.subject, "human_friendly", str(cert.subject)),
                "serial_number": str(getattr(cert, "serial_number", "")),
                "sha256_fingerprint": sha256_fp,
                "sha1_fingerprint": sha1_fp
            }

            # Extract validity timestamps if available
            if hasattr(cert, "valid_before"):
                cert_data["valid_before"] = str(cert.valid_before)
            if hasattr(cert, "valid_after"):
                cert_data["valid_after"] = str(cert.valid_after)

            certificate_list.append(cert_data)

        return {
            "status": "SUCCESS",
            "certificate_count": len(certificate_list),
            "certificates": certificate_list
        }

    except Exception as e:
        return {
            "status": "FAILED",
            "certificate_count": 0,
            "certificates": [],
            "error": str(e)
        }