from datetime import datetime


def get_lifecycle_status(twin):

    version_count = len(
        twin.versions
    )

    if version_count == 0:
        state = "Empty"

    elif version_count == 1:
        state = "Created"

    else:
        state = "Active"

    return {
        "twin_id": twin.id,
        "package_name": twin.package_name,
        "app_name": twin.app_name,
        "state": state,
        "version_count": version_count,
        "current_version":
            twin.current_version,
        "created_at":
            twin.created_at,
        "last_updated":
            twin.updated_at
    }