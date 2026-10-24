"""
Threat Memory heuristic threshold configuration parameters.
These threshold values serve as initial heuristic baselines for similarity classification.
"""

# DNA Similarity Thresholds (%)
HIGH_SIMILARITY_THRESHOLD = 65.0
RELATED_SAMPLE_THRESHOLD = 35.0

# Threat Memory Status Definitions
STATUS_KNOWN_EXACT = "KNOWN_EXACT"
STATUS_HIGH_SIMILARITY = "HIGH_SIMILARITY"
STATUS_RELATED_SAMPLE = "RELATED_SAMPLE"
STATUS_NEW_SAMPLE = "NEW_SAMPLE"
STATUS_ERROR = "ERROR"
