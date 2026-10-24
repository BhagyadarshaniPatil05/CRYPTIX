from pathlib import Path


def get_rule_files():
    """
    Return all .yar rule files.
    """

    rules_dir = Path(__file__).parent / "rules"

    return list(rules_dir.glob("*.yar"))