from app.intelligence.dangerous_permissions import DANGEROUS_PERMISSIONS


def analyze_permissions(permission_list):
    """
    Analyze APK permissions and classify dangerous ones.
    """

    dangerous = []

    for permission in permission_list:

        if permission in DANGEROUS_PERMISSIONS:

            info = DANGEROUS_PERMISSIONS[permission]

            dangerous.append({

                "permission": permission,

                "severity": info["severity"],

                "reason": info["reason"]

            })

    return dangerous