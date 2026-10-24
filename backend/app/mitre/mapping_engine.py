"""
Deterministic Mapping Engine for MITRE ATT&CK for Mobile (v15.1).
Normalizes static analysis findings, evaluates mapping rules, computes confidence levels,
deduplicates mappings, and correlates IOCs and Threat Intelligence records.
"""
import logging
from typing import Dict, Any, List

from app.mitre.catalog import get_technique, ATTACK_VERSION
from app.mitre.rules import MITRE_RULES

logger = logging.getLogger("cryptix.mitre.engine")


def extract_normalized_evidence(analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalizes diverse analyzer outputs from static analysis into flat evidence items.
    """
    evidence_items = []

    if not analysis_results or not isinstance(analysis_results, dict):
        return evidence_items

    # 1. DEX Findings
    dex_findings = analysis_results.get("dex_findings", []) or []
    for dex in dex_findings:
        if isinstance(dex, dict) and "api" in dex:
            evidence_items.append({
                "type": "DEX_BEHAVIOR",
                "key": dex["api"],
                "reference": dex["api"],
                "summary": dex.get("reason") or f"DEX class/method pattern '{dex['api']}'",
            })

    # 2. Static Behaviors
    behaviors = analysis_results.get("behaviors", []) or []
    for beh in behaviors:
        if isinstance(beh, dict) and "api" in beh:
            evidence_items.append({
                "type": "STATIC_BEHAVIOR",
                "key": beh["api"],
                "reference": beh["api"],
                "summary": beh.get("reason") or f"Static behavior signature '{beh['api']}'",
            })

    # 3. Dangerous Permissions
    dangerous_perms = analysis_results.get("dangerous_permissions", []) or []
    for perm in dangerous_perms:
        if isinstance(perm, dict) and "permission" in perm:
            evidence_items.append({
                "type": "DANGEROUS_PERMISSION",
                "key": perm["permission"],
                "reference": perm["permission"],
                "summary": perm.get("reason") or f"Manifest permission '{perm['permission']}'",
            })

    # 4. Intent Filters
    intent_filters = analysis_results.get("intent_filters", []) or []
    for filter_item in intent_filters:
        filter_str = str(filter_item)
        if "BOOT_COMPLETED" in filter_str:
            evidence_items.append({
                "type": "MANIFEST_INTENT",
                "key": "BOOT_COMPLETED",
                "reference": "android.intent.action.BOOT_COMPLETED",
                "summary": "Intent filter registers for system boot completion broadcast.",
            })
        if "SMS_RECEIVED" in filter_str or "RECEIVE_SMS" in filter_str:
            evidence_items.append({
                "type": "MANIFEST_INTENT",
                "key": "SMS_RECEIVED",
                "reference": "android.provider.Telephony.SMS_RECEIVED",
                "summary": "Intent filter registers for incoming SMS broadcast.",
            })

    # 5. Extracted IOCs (Separated from direct ATT&CK behavior unless behavioral rule exists)
    indicators = analysis_results.get("indicators", {}) or {}
    if isinstance(indicators, dict):
        if indicators.get("api_keys"):
            evidence_items.append({
                "type": "IOC_INDICATOR",
                "key": "api_keys",
                "reference": f"{len(indicators['api_keys'])} Extracted API Key(s)",
                "summary": "Extracted hardcoded API key patterns embedded in binary.",
            })

    # 6. YARA Matches
    yara_matches = analysis_results.get("yara_matches", []) or []
    for yara in yara_matches:
        if isinstance(yara, dict) and "rule" in yara:
            evidence_items.append({
                "type": "YARA_MATCH",
                "key": yara["rule"],
                "reference": f"YARA:{yara['rule']}",
                "summary": f"Matched YARA malware signature rule '{yara['rule']}'",
            })

    return evidence_items


def map_evidence_to_mitre(analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Executes deterministic rule matching to map normalized evidence items to MITRE Mobile ATT&CK techniques.
    """
    evidence_items = extract_normalized_evidence(analysis_results)
    if not evidence_items:
        logger.info("No evidence items available for MITRE ATT&CK mapping.")
        return []

    raw_mappings = []

    for item in evidence_items:
        item_type = item["type"]
        item_key = item["key"]

        for rule in MITRE_RULES:
            if rule["evidence_type"] == item_type and rule["evidence_key"] == item_key:
                tech_meta = get_technique(rule["technique_id"])
                if not tech_meta:
                    continue

                summary_text = (
                    f"{rule['explanation']} Limitation: {rule.get('limitation', 'Static analysis indicates candidate capability only.')}"
                )

                raw_mappings.append({
                    "rule_id": rule["rule_id"],
                    "technique_id": rule["technique_id"],
                    "technique_name": tech_meta["technique_name"],
                    "tactic": tech_meta["tactic"],
                    "evidence_type": item_type,
                    "evidence_reference": item["reference"],
                    "evidence_summary": summary_text,
                    "confidence": rule["confidence"],
                    "attack_version": ATTACK_VERSION,
                })

    # Confidence elevation check: permission + DEX API supporting evidence elevates confidence to HIGH
    technique_groups = {}
    for m in raw_mappings:
        tid = m["technique_id"]
        if tid not in technique_groups:
            technique_groups[tid] = []
        technique_groups[tid].append(m)

    deduplicated_mappings = []

    for tid, mappings in technique_groups.items():
        has_permission = any(m["evidence_type"] == "DANGEROUS_PERMISSION" for m in mappings)
        has_behavior = any(m["evidence_type"] in ("DEX_BEHAVIOR", "STATIC_BEHAVIOR") for m in mappings)

        seen_refs = set()
        for m in mappings:
            ref_key = (m["technique_id"], m["evidence_reference"])
            if ref_key in seen_refs:
                continue
            seen_refs.add(ref_key)

            # Elevate permission confidence to HIGH if supported by DEX behavior
            if m["evidence_type"] == "DANGEROUS_PERMISSION" and has_behavior and has_permission:
                m["confidence"] = "HIGH"
                m["evidence_summary"] += " [Confidence elevated to HIGH due to supporting DEX API bytecode evidence]."

            deduplicated_mappings.append(m)

    return deduplicated_mappings
