from pathlib import Path
from lxml import etree

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def analyze_intent_filters(decoded_folder: str):
    """
    Analyze Android intent filters from AndroidManifest.xml.
    """

    if not decoded_folder:
        return []

    manifest_path = Path(decoded_folder) / "AndroidManifest.xml"

    if not manifest_path.exists():
        return []

    try:
        tree = etree.parse(str(manifest_path))
        root = tree.getroot()
    except Exception:
        return []

    application = root.find("application")

    if application is None:
        return []

    findings = []

    for activity in application.findall("activity"):

        activity_name = activity.get(
            ANDROID_NS + "name"
        )

        for intent_filter in activity.findall("intent-filter"):

            actions = []
            categories = []

            for action in intent_filter.findall("action"):

                action_name = action.get(
                    ANDROID_NS + "name"
                )

                if action_name:
                    actions.append(action_name)

            for category in intent_filter.findall("category"):

                category_name = category.get(
                    ANDROID_NS + "name"
                )

                if category_name:
                    categories.append(category_name)

            findings.append(
                {
                    "activity": activity_name,
                    "actions": actions,
                    "categories": categories
                }
            )

    return findings