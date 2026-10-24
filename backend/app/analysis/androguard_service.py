from androguard.misc import AnalyzeAPK
from app.core.logger import logger


def analyze_apk(apk_path: str):
    """
    Analyze APK using Androguard
    """

    try:
        logger.info(f"Starting APK analysis: {apk_path}")

        apk, dex, analysis = AnalyzeAPK(apk_path)

        result = {
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": apk.get_permissions(),
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
        }

        logger.info("APK analysis completed successfully")

        return result

    except Exception as e:
        logger.error(f"APK analysis failed: {str(e)}")
        raise