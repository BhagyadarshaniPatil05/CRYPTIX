import hashlib


def generate_sha256(file_path: str) -> str:
    """
    Generate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def generate_sha256_from_file_object(file_obj) -> str:
    """
    Generate SHA-256 hash directly from a file-like object stream.
    Resets stream position (seek 0) after calculation.
    """
    sha256 = hashlib.sha256()

    file_obj.seek(0)
    while True:
        chunk = file_obj.read(8192)
        if not chunk:
            break
        sha256.update(chunk)

    file_obj.seek(0)
    return sha256.hexdigest()