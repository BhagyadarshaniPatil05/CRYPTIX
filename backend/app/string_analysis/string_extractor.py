from androguard.misc import AnalyzeAPK


def extract_strings(apk_path: str):
    """
    Extract all strings from the DEX files inside an APK.
    """

    try:
        _, dex_list, _ = AnalyzeAPK(apk_path)

        strings = set()

        # Handle one or more DEX files
        if not isinstance(dex_list, list):
            dex_list = [dex_list]

        for dex in dex_list:
            for string in dex.get_strings():
                strings.add(str(string))

        return sorted(strings)

    except Exception as e:
        print("String Extraction Error:", e)
        return []