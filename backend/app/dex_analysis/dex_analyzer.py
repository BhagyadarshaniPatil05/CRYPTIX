from androguard.misc import AnalyzeAPK
from app.dex_analysis.api_patterns import API_PATTERNS


def analyze_dex(apk_path: str):
    """
    Analyze DEX bytecode using class and method references.
    """

    findings = []

    try:
        apk, dex_list, analysis = AnalyzeAPK(apk_path)

        if not isinstance(dex_list, list):
            dex_list = [dex_list]

        seen = set()

        for dex in dex_list:

            # Analyze classes
            for cls in dex.get_classes():

                class_name = cls.get_name()

                for api in API_PATTERNS:

                    if api in class_name and api not in seen:

                        seen.add(api)

                        findings.append({
                            "api": api,
                            "category": API_PATTERNS[api]["category"],
                            "severity": API_PATTERNS[api]["severity"],
                            "reason": API_PATTERNS[api]["reason"]
                        })

                # Analyze methods
                for method in cls.get_methods():

                    method_name = method.get_name()

                    for api in API_PATTERNS:

                        if api in method_name and api not in seen:

                            seen.add(api)

                            findings.append({
                                "api": api,
                                "category": API_PATTERNS[api]["category"],
                                "severity": API_PATTERNS[api]["severity"],
                                "reason": API_PATTERNS[api]["reason"]
                            })

        return findings

    except Exception as e:

        return [{
            "api": "Analysis Error",
            "category": "DEX",
            "severity": "Low",
            "reason": str(e)
        }]