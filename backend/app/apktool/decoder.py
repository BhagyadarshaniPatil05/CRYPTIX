import shutil
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger("cryptix.apktool")

# Project root
BASE_DIR = Path(__file__).resolve().parents[3]

# APKTool executable
APKTOOL_JAR = BASE_DIR / "tools" / "apktool" / "apktool.jar"

# Decoded APK output folder
DECODED_DIR = BASE_DIR / "decoded"
DECODED_DIR.mkdir(exist_ok=True)


def decode_apk(apk_path: str):
    """
    Decode an APK using APKTool.
    Returns the path to the decoded folder as a string, or None if decoding fails.
    """
    apk_path = Path(apk_path)

    if not apk_path.exists():
        logger.error(f"APK file not found for decoding: {apk_path}")
        return None

    if not APKTOOL_JAR.exists():
        logger.error(f"APKTool JAR not found at: {APKTOOL_JAR}")
        return None

    if not shutil.which("java"):
        logger.warning("Java executable not found in PATH. Skipping APKTool decoding.")
        return None

    output_folder = DECODED_DIR / apk_path.stem

    command = [
        "java",
        "-jar",
        str(APKTOOL_JAR),
        "d",
        "-f",
        str(apk_path),
        "-o",
        str(output_folder)
    ]

    try:
        subprocess.run(
            command,
            check=True,
            timeout=60,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return str(output_folder)

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, Exception) as e:
        logger.error(f"APKTool decoding failed for {apk_path.name}: {str(e)}")

        # Cleanup failed output folder if left behind
        if output_folder.exists():
            try:
                shutil.rmtree(output_folder)
            except Exception:
                pass

        return None