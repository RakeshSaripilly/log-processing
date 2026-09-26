"""
Unit tests for ULPF 10 Decoders
Team LunarX - SIH26156 (NTRO)
"""

from core.decoders import (
    decode_syslog_rfc3164,
    decode_syslog_rfc5424,
    decode_keyvalue,
    decode_csv_line,
    decode_cef,
    decode_leef,
    decode_json,
    decode_xml,
    decode_regex
)
from core.salvage import extract_observables


def test_syslog_rfc3164():
    raw = "<34>Oct 11 22:14:15 myhost su[123]: 'su root' failed for lonvick on /dev/pts/8"
    res = decode_syslog_rfc3164(raw)
    assert res is not None
    assert res["pri"] == "34"
    assert res["hostname"] == "myhost"
    assert res["app"] == "su"
    assert res["pid"] == "123"
    assert res["severity"] == 2  # 34 & 7


def test_syslog_rfc5424():
    raw = '<165>1 2026-09-26T22:14:15.003Z edge-firewall myproc 1245 ID47 [exampleSDID@32473 iut="3"] Event occurred'
    res = decode_syslog_rfc5424(raw)
    assert res is not None
    assert res["pri"] == "165"
    assert res["hostname"] == "edge-firewall"
    assert res["app"] == "myproc"


def test_keyvalue():
    raw = 'srcip=192.0.2.1 dstip=198.51.100.2 action="permit connection" duration=120'
    res = decode_keyvalue(raw)
    assert res is not None
    assert res["srcip"] == "192.0.2.1"
    assert res["action"] == "permit connection"
    assert res["duration"] == "120"


def test_csv_line():
    raw = "2026-09-26,DROP,192.0.2.55,443,TCP"
    headers = ["time", "action", "src_ip", "port", "proto"]
    res = decode_csv_line(raw, delimiter=",", headers=headers)
    assert res is not None
    assert res["action"] == "DROP"
    assert res["src_ip"] == "192.0.2.55"


def test_cef():
    raw = "CEF:0|Security|ThreatManager|1.0|100|Worm detected|10|src=192.0.2.14 dst=198.51.100.4 spt=1234 dpt=80"
    res = decode_cef(raw)
    assert res is not None
    assert res["device_vendor"] == "Security"
    assert res["name"] == "Worm detected"
    assert res["extension"]["src"] == "192.0.2.14"


def test_leef():
    raw = "LEEF:2.0|Microsoft|MSExchange|4.0|15345|src=192.0.2.22\tdst=198.51.100.33"
    res = decode_leef(raw)
    assert res is not None
    assert res["vendor"] == "Microsoft"
    assert res["product"] == "MSExchange"


def test_json():
    raw = '{"user": "analyst", "ip": "192.0.2.88", "action": "login"}'
    res = decode_json(raw)
    assert res is not None
    assert res["user"] == "analyst"


def test_xml():
    raw = "<Event><Data Name='User'>admin</Data><Data Name='IP'>192.0.2.99</Data></Event>"
    res = decode_xml(raw)
    assert res is not None
    assert "Event" in res


def test_regex():
    raw = "LOGIN SUCCESS user=john ip=192.0.2.10"
    pat = r"LOGIN (?P<status>\w+) user=(?P<user>\w+) ip=(?P<ip>\S+)"
    res = decode_regex(raw, pat)
    assert res is not None
    assert res["status"] == "SUCCESS"
    assert res["user"] == "john"


def test_salvage_observables():
    raw = "An unknown intrusion alert from 192.0.2.50 to port: 443 with sha256: 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
    obs = extract_observables(raw)
    assert "192.0.2.50" in obs["ip_addresses"]
    assert 443 in obs["ports"]
    assert "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b" in obs["hashes_sha256"]
