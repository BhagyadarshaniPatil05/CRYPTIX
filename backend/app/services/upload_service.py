import shutil

from app.config.settings import settings

# Create upload folder if it doesn't exist
settings.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


ZIP_MAGIC_HEADER = b"PK\x03\x04"


def validate_apk(upload_file) -> tuple[bool, str]:
    """
    Validate uploaded file:
    1. Extension check (.apk)
    2. Container check: ZIP magic bytes (PK\x03\x04).
       Note: Verifies ZIP container structure used by APKs;
       does not prove valid Android bytecode or safety.
    """
    if not upload_file.filename or not upload_file.filename.lower().endswith(".apk"):
        return False, "Only files with .apk extension are allowed."

    try:
        upload_file.file.seek(0)
        header = upload_file.file.read(4)
        upload_file.file.seek(0)

        if header != ZIP_MAGIC_HEADER:
            return False, "Invalid file format. File must be a valid ZIP/APK archive container."

    except Exception as e:
        return False, f"Failed to read file content for validation: {str(e)}"

    return True, ""


def save_apk(upload_file) -> str:
    """
    Legacy upload save wrapper for backward compatibility.
    """
    file_path = settings.UPLOAD_FOLDER / upload_file.filename

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

    return str(file_path)


def save_apk_by_hash(upload_file, sha256: str) -> str:
    """
    Save uploaded APK permanently using its SHA-256 hash filename
    to prevent filename collisions and overwriting existing files.
    """
    target_path = settings.UPLOAD_FOLDER / f"{sha256}.apk"

    # If file already exists under this hash, return path without overwriting
    if target_path.exists():
        return str(target_path)

    temp_path = settings.UPLOAD_FOLDER / f"{sha256}.tmp"

    try:
        upload_file.file.seek(0)
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)

        # Atomic rename from temp to permanent SHA-256 path
        temp_path.replace(target_path)
        upload_file.file.seek(0)

        return str(target_path)

    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise