from pathlib import Path
from lxml import etree

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def analyze_exported_components(decoded_folder: str):
    """
    Analyze exported Android components from AndroidManifest.xml.
    """

    empty_result = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": []
    }

    if not decoded_folder:
        return empty_result

    manifest_path = Path(decoded_folder) / "AndroidManifest.xml"

    if not manifest_path.exists():
        return empty_result

    try:
        tree = etree.parse(str(manifest_path))
        root = tree.getroot()
    except Exception:
        return empty_result

    application = root.find("application")

    if application is None:
        return empty_result

    result = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": []
    }

    component_tags = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers"
    }

    for tag, key in component_tags.items():

        for component in application.findall(tag):

            name = component.get(
                ANDROID_NS + "name"
            )

            exported = component.get(
                ANDROID_NS + "exported"
            )

            if exported == "true":

                result[key].append(
                    {
                        "name": name,
                        "exported": True
                    }
                )

    return result