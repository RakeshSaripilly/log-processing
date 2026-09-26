"""
Universal Log Pre-processing Framework (ULPF) - 10 Core Decoders
Decoders: syslog_rfc3164, syslog_rfc5424, keyvalue, csv, cef, leef, json, xml, regex, salvage
Team LunarX - SIH26156 (NTRO)
"""

import re
import csv
import json
import io
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, Tuple, List

# RFC 3164 regex: <PRI>Mmm dd hh:mm:ss hostname app[pid]: message
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[^\s:]+)\s+(?P<app>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# RFC 5424 regex: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>[^\s]+)\s+(?P<hostname>[^\s]+)\s+"
    r"(?P<app>[^\s]+)\s+(?P<procid>[^\s]+)\s+(?P<msgid>[^\s]+)\s+"
    r"(?P<sd>-|\[.*?\])(?:\s+(?P<message>.*))?$"
)

# CEF pattern: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
CEF_PATTERN = re.compile(
    r"^CEF:(?P<cef_version>\d+)\|(?P<device_vendor>[^|]*)\|(?P<device_product>[^|]*)\|"
    r"(?P<device_version>[^|]*)\|(?P<device_event_class_id>[^|]*)\|(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)(?:\|(?P<extension>.*))?$"
)

# LEEF pattern: LEEF:Version|Vendor|Product|Version|EventID|Extension
LEEF_PATTERN = re.compile(
    r"^LEEF:(?P<leef_version>[^|]+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<extension>.*)$"
)

# Key-Value pairs parser (handles key=val, key="spaced val", key='spaced val')
KV_PATTERN = re.compile(
    r'(?P<key>[a-zA-Z0-9_\.\-]+)=(?P<val>"[^"]*"|\'[^\']*\'|[^\s]+)'
)


def decode_syslog_rfc3164(text: str) -> Optional[Dict[str, Any]]:
    match = RFC3164_PATTERN.match(text.strip())
    if not match:
        return None
    res = match.groupdict()
    pri = int(res["pri"])
    res["facility"] = pri >> 3
    res["severity"] = pri & 0x07
    return res


def decode_syslog_rfc5424(text: str) -> Optional[Dict[str, Any]]:
    match = RFC5424_PATTERN.match(text.strip())
    if not match:
        return None
    res = match.groupdict()
    pri = int(res["pri"])
    res["facility"] = pri >> 3
    res["severity"] = pri & 0x07
    return res


def decode_keyvalue(text: str) -> Optional[Dict[str, Any]]:
    matches = KV_PATTERN.findall(text)
    if not matches:
        return None
    res = {}
    for k, v in matches:
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        res[k] = v
    return res if len(res) >= 2 else None


def decode_csv_line(text: str, delimiter: str = ",", headers: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    try:
        reader = csv.reader(io.StringIO(text.strip()), delimiter=delimiter)
        row = next(reader)
        if not row:
            return None
        if headers:
            return {headers[i]: row[i] for i in range(min(len(headers), len(row)))}
        return {f"col_{i}": val for i, val in enumerate(row)}
    except Exception:
        return None


def decode_cef(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    match = CEF_PATTERN.match(text)
    if not match:
        # Check if CEF is embedded inside syslog header
        cef_idx = text.find("CEF:")
        if cef_idx != -1:
            match = CEF_PATTERN.match(text[cef_idx:])
    if not match:
        return None

    res = match.groupdict()
    ext = res.pop("extension", "")
    if ext:
        ext_kvs = decode_keyvalue(ext)
        if ext_kvs:
            res["extension"] = ext_kvs
    return res


def decode_leef(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    match = LEEF_PATTERN.match(text)
    if not match:
        leef_idx = text.find("LEEF:")
        if leef_idx != -1:
            match = LEEF_PATTERN.match(text[leef_idx:])
    if not match:
        return None

    res = match.groupdict()
    ext = res.pop("extension", "")
    if ext:
        # Check optional delimiter parameter in LEEF 2.0
        sep = "\t" if "\t" in ext else " "
        matches = KV_PATTERN.findall(ext)
        if matches:
            res["extension"] = {k: v.strip('"\'') for k, v in matches}
    return res


def decode_json(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    if not (text.startswith("{") and text.endswith("}")):
        # Look for first { and last }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
        else:
            return None
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        return {"data": data}
    except Exception:
        return None


def decode_xml(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    if not (text.startswith("<") and text.endswith(">")):
        start = text.find("<")
        end = text.rfind(">")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
        else:
            return None
    try:
        root = ET.fromstring(text)
        def _xml_to_dict(node):
            res = {}
            for child in node:
                child_data = _xml_to_dict(child)
                tag = child.tag.split("}")[-1]  # remove namespace
                if tag in res:
                    if not isinstance(res[tag], list):
                        res[tag] = [res[tag]]
                    res[tag].append(child_data)
                else:
                    res[tag] = child_data
            text_val = (node.text or "").strip()
            if text_val and not res:
                return text_val
            if text_val:
                res["#text"] = text_val
            res.update({f"@{k}": v for k, v in node.attrib.items()})
            return res
        return {root.tag.split("}")[-1]: _xml_to_dict(root)}
    except Exception:
        return None


def decode_regex(text: str, pattern: str) -> Optional[Dict[str, Any]]:
    try:
        rgx = re.compile(pattern)
        m = rgx.search(text)
        if m:
            return m.groupdict()
    except Exception:
        pass
    return None


DECODER_REGISTRY = {
    "syslog_rfc3164": decode_syslog_rfc3164,
    "syslog_rfc5424": decode_syslog_rfc5424,
    "keyvalue": decode_keyvalue,
    "csv": decode_csv_line,
    "cef": decode_cef,
    "leef": decode_leef,
    "json": decode_json,
    "xml": decode_xml,
    "regex": decode_regex
}
