import logging
from sqlalchemy.orm import Session

from app.database.crud import get_apk_by_id
from app.analysis.androguard_service import analyze_apk
from app.security.manifest_analyzer import analyze_permissions
from app.security.risk_engine import calculate_risk_score
from app.apktool.decoder import decode_apk
from app.manifest.exported_analyzer import analyze_exported_components
from app.manifest.intent_filter_analyzer import analyze_intent_filters
from app.certificate.certificate_analyzer import analyze_certificate
from app.string_analysis.string_extractor import extract_strings
from app.string_analysis.indicator_detector import detect_indicators
from app.behavior_analysis.behavior_detector import detect_behaviors
from app.yara_engine.yara_scanner import scan_with_yara
from app.agents.agent_models import AgentAnalysisInput
from app.agents.malware_agent import analyze_threat
from app.dex_analysis.dex_analyzer import analyze_dex
from app.digital_twin.twin_engine import create_digital_twin
from app.digital_twin.digital_twin_service import save_digital_twin
from app.malware_dna.dna_service import generate_and_store_dna
from app.threat_memory.memory_service import evaluate_and_store_threat_memory
from app.threat_intelligence.service import enrich_sample_threat_intelligence
from app.mitre.service import evaluate_and_store_mitre_mappings

logger = logging.getLogger("cryptix.pipeline")


def analyze_uploaded_apk(db: Session, apk_id: int):
    """
    Complete resilient APK static analysis pipeline.
    Individual analyzer failures are captured cleanly without crashing the overall request.
    """

    # -----------------------------
    # Get APK from database
    # -----------------------------
    apk = get_apk_by_id(db, apk_id)

    if not apk:
        return None

    analyzer_status = {}

    # -----------------------------
    # 1. Reverse Engineering (Androguard)
    # -----------------------------
    try:
        result = analyze_apk(apk.file_path)
        analyzer_status["androguard"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Androguard analysis failed for APK {apk_id}: {str(e)}")
        analyzer_status["androguard"] = {"status": "FAILED", "error": str(e)}
        result = {
            "package_name": apk.package_name or "unknown.package",
            "app_name": apk.file_name or "Unknown App",
            "version_name": apk.version or "1.0",
            "version_code": "1",
            "min_sdk": "Unknown",
            "target_sdk": "Unknown",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": []
        }

    # Populate explicit database metadata onto result object
    result["apk_id"] = apk.id
    result["sha256"] = apk.sha256
    result["file_name"] = apk.file_name
    result["file_size"] = apk.file_size

    # -----------------------------
    # 2. Decode APK using APKTool
    # -----------------------------
    try:
        decoded_folder = decode_apk(apk.file_path)
        if decoded_folder:
            analyzer_status["apktool"] = {"status": "SUCCESS"}
        else:
            analyzer_status["apktool"] = {"status": "FAILED", "error": "APKTool decoding skipped or failed"}
    except Exception as e:
        logger.error(f"APKTool decoding exception for APK {apk_id}: {str(e)}")
        analyzer_status["apktool"] = {"status": "FAILED", "error": str(e)}
        decoded_folder = None

    # -----------------------------
    # 3. Exported Component Analysis
    # -----------------------------
    try:
        exported = analyze_exported_components(decoded_folder)
        result["exported_components"] = exported
        analyzer_status["exported_components"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Exported component analysis failed for APK {apk_id}: {str(e)}")
        analyzer_status["exported_components"] = {"status": "FAILED", "error": str(e)}
        result["exported_components"] = {"activities": [], "services": [], "receivers": [], "providers": []}

    # -----------------------------
    # 4. Intent Filter Analysis
    # -----------------------------
    try:
        intent_filters = analyze_intent_filters(decoded_folder)
        result["intent_filters"] = intent_filters
        analyzer_status["intent_filters"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Intent filter analysis failed for APK {apk_id}: {str(e)}")
        analyzer_status["intent_filters"] = {"status": "FAILED", "error": str(e)}
        result["intent_filters"] = []

    # -----------------------------
    # 5. Manifest Intelligence (Dangerous Permissions)
    # -----------------------------
    try:
        dangerous_permissions = analyze_permissions(result.get("permissions", []))
        analyzer_status["manifest_permissions"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Permission analysis failed for APK {apk_id}: {str(e)}")
        analyzer_status["manifest_permissions"] = {"status": "FAILED", "error": str(e)}
        dangerous_permissions = []

    # -----------------------------
    # 6. Certificate Analysis
    # -----------------------------
    try:
        certificate = analyze_certificate(apk.file_path)
        result["certificate"] = certificate
        analyzer_status["certificate"] = {"status": certificate.get("status", "SUCCESS")}
    except Exception as e:
        logger.error(f"Certificate analysis failed for APK {apk_id}: {str(e)}")
        analyzer_status["certificate"] = {"status": "FAILED", "error": str(e)}
        result["certificate"] = {"certificate_count": 0, "certificates": [], "error": str(e)}

    # -----------------------------
    # 7. String Extraction & 8. Indicator Detection
    # -----------------------------
    try:
        strings = extract_strings(apk.file_path)
        indicators = detect_indicators(strings)
        result["indicators"] = indicators
        analyzer_status["strings_and_indicators"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"String/Indicator extraction failed for APK {apk_id}: {str(e)}")
        analyzer_status["strings_and_indicators"] = {"status": "FAILED", "error": str(e)}
        strings = []
        result["indicators"] = {"urls": [], "ip_addresses": [], "emails": [], "firebase_urls": [], "api_keys": [], "base64_strings": [], "bitcoin_addresses": []}

    # -----------------------------
    # 9. Suspicious Static Behavior Detection
    # -----------------------------
    try:
        behaviors = detect_behaviors(strings)
        result["behaviors"] = behaviors
        analyzer_status["behavior_analysis"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Behavior detection failed for APK {apk_id}: {str(e)}")
        analyzer_status["behavior_analysis"] = {"status": "FAILED", "error": str(e)}
        behaviors = []
        result["behaviors"] = []

    # -----------------------------
    # 10. DEX Bytecode Analysis
    # -----------------------------
    try:
        dex_findings = analyze_dex(apk.file_path)
        result["dex_findings"] = dex_findings
        analyzer_status["dex_analysis"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"DEX analysis failed for APK {apk_id}: {str(e)}")
        analyzer_status["dex_analysis"] = {"status": "FAILED", "error": str(e)}
        dex_findings = []
        result["dex_findings"] = []

    # -----------------------------
    # 11. YARA Malware Signature Scan
    # -----------------------------
    try:
        yara_matches = scan_with_yara(apk.file_path)
        result["yara_matches"] = yara_matches
        analyzer_status["yara_scan"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"YARA scan failed for APK {apk_id}: {str(e)}")
        analyzer_status["yara_scan"] = {"status": "FAILED", "error": str(e)}
        yara_matches = []
        result["yara_matches"] = []

    # -----------------------------
    # 12. Risk Score Calculation
    # -----------------------------
    risk = calculate_risk_score(
        dangerous_permissions,
        behaviors,
        yara_matches
    )

    result["dangerous_permissions"] = dangerous_permissions
    result["risk_score"] = risk["risk_score"]
    result["risk_level"] = risk["risk_level"]
    result["analyzer_status"] = analyzer_status

    # -----------------------------
    # 13. Malware Analysis Agent (Rule-Based Summarizer)
    # -----------------------------
    agent_input = AgentAnalysisInput(
        package_name=result["package_name"],
        app_name=result["app_name"],
        permissions=result.get("permissions", []),
        dangerous_permissions=dangerous_permissions,
        exported_components=result["exported_components"],
        intent_filters=result["intent_filters"],
        certificate=result["certificate"],
        indicators=result["indicators"],
        behaviors=behaviors,
        dex_findings=dex_findings,
        yara_matches=yara_matches,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"]
    )

    threat_assessment = analyze_threat(agent_input)
    result["threat_assessment"] = threat_assessment.model_dump()

    # -----------------------------
    # 14. Digital Twin Creation & Persistence
    # -----------------------------
    digital_twin = create_digital_twin(result)
    result["digital_twin"] = digital_twin.model_dump()

    try:
        saved_twin, saved_version = save_digital_twin(
            db=db,
            apk=apk,
            twin=digital_twin
        )
        result["digital_twin_id"] = saved_twin.id
        result["digital_twin_version"] = saved_version.version_number
    except Exception as e:
        logger.error(f"Digital Twin persistence failed for APK {apk_id}: {str(e)}")

    # -----------------------------
    # 15. Malware DNA Fingerprinting & Persistence
    # -----------------------------
    try:
        dna_record = generate_and_store_dna(
            db=db,
            apk_id=apk.id,
            analysis_results=result
        )
        result["malware_dna_hash"] = dna_record.dna_hash
        result["malware_dna_feature_count"] = dna_record.feature_count
        analyzer_status["malware_dna"] = {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Malware DNA fingerprinting failed for APK {apk_id}: {str(e)}")
        analyzer_status["malware_dna"] = {"status": "FAILED", "error": str(e)}
        result["malware_dna_hash"] = None
        result["malware_dna_feature_count"] = 0

    # -----------------------------
    # 16. Threat Memory Evaluation & Persistence
    # -----------------------------
    try:
        memory_record = evaluate_and_store_threat_memory(
            db=db,
            apk_id=apk.id
        )
        result["threat_memory_status"] = memory_record.status
        analyzer_status["threat_memory"] = {"status": "SUCCESS", "decision": memory_record.status}
    except Exception as e:
        logger.error(f"Threat Memory evaluation failed for APK {apk_id}: {str(e)}")
        analyzer_status["threat_memory"] = {"status": "FAILED", "error": str(e)}
        result["threat_memory_status"] = "ERROR"

    # -----------------------------
    # 17. Global Threat Intelligence Enrichment
    # -----------------------------
    try:
        ti_records = enrich_sample_threat_intelligence(
            db=db,
            apk_id=apk.id,
            analysis_results=result
        )
        result["threat_intelligence_count"] = len(ti_records)
        analyzer_status["threat_intelligence"] = {"status": "SUCCESS", "count": len(ti_records)}
    except Exception as e:
        logger.error(f"Threat Intelligence enrichment failed for APK {apk_id}: {str(e)}")
        analyzer_status["threat_intelligence"] = {"status": "FAILED", "error": str(e)}
        result["threat_intelligence_count"] = 0

    # -----------------------------
    # 18. MITRE ATT&CK + IOC Intelligence Mapping
    # -----------------------------
    try:
        mitre_mappings = evaluate_and_store_mitre_mappings(
            db=db,
            apk_id=apk.id,
            analysis_results=result
        )
        result["mitre_mappings_count"] = len(mitre_mappings)
        analyzer_status["mitre_mapping"] = {"status": "SUCCESS", "count": len(mitre_mappings)}
    except Exception as e:
        logger.error(f"MITRE ATT&CK mapping failed for APK {apk_id}: {str(e)}")
        analyzer_status["mitre_mapping"] = {"status": "FAILED", "error": str(e)}
        result["mitre_mappings_count"] = 0

    return result