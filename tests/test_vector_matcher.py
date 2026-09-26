"""
Unit tests for Telemetry-Aware Vector Matcher & Confidence Routing
Team LunarX - SIH26156 (NTRO)
"""

from core.vector_matcher import TelemetryVectorMatcher, infer_data_type


def test_type_inference():
    assert infer_data_type("client_ip", ["192.0.2.14", "192.0.2.15"]) == "ip"
    assert infer_data_type("sport", ["54322", "80"]) == "port"
    assert infer_data_type("mac_addr", ["00:1A:2B:3C:4D:5E"]) == "mac"
    assert infer_data_type("link", ["https://example.com/api/v1"]) == "url"
    assert infer_data_type("flag", ["true", "false"]) == "bool"


def test_confidence_routing_auto_map():
    vm = TelemetryVectorMatcher()
    res = vm.map_field("source_ip", ["192.0.2.100", "192.0.2.101"], vendor_hint="cisco")
    assert res["decision"] == "AUTO_MAP"
    assert res["target_field"] == "src_endpoint.ip"
    assert res["confidence"] >= 0.85


def test_confidence_routing_review_queue():
    vm = TelemetryVectorMatcher()
    # Unfamiliar key name with partial keyword & matching type that falls into 0.60 - 0.85 review band
    res = vm.map_field("client_station", ["remote-box-1"], vendor_hint="custom_vpn")
    assert res["decision"] == "HUMAN_REVIEW"


def test_confidence_routing_custom_fallback():
    vm = TelemetryVectorMatcher()
    # Bizarre vendor field unrelated to OCSF canonical fields
    res = vm.map_field("liquid_cooling_pump_rpm", ["4200"], vendor_hint="supermicro")
    assert res["decision"] in ("CUSTOM_FALLBACK", "HUMAN_REVIEW")
    if res["decision"] == "CUSTOM_FALLBACK":
        assert res["target_field"].startswith("custom.supermicro.")
