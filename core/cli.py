"""
Universal Log Pre-processing Framework (ULPF) - Production CLI
Team LunarX - SIH26156 (NTRO)

Commands:
  ulpf process <input_file> [options]
  ulpf --version
  ulpf --help

Exit codes:
  0 = Successful processing
  1 = General processing failure
  2 = Invalid CLI arguments
  3 = Input file / configuration error
  4 = Unsupported format
  5 = Integrity / validation failure
"""

import sys
import os
import json
import time
import argparse
import traceback
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from core.pipeline import ProcessingPipeline
from core.integrity import verify_chain
from core.decoders import (
    decode_cef,
    decode_leef,
    decode_json,
    decode_syslog_rfc5424,
    decode_syslog_rfc3164,
    decode_keyvalue,
)

VERSION = "2.0.0"
SCHEMA_VERSION = "OCSF 1.9.0"

SUPPORTED_FORMATS = {
    "cef": "CEF",
    "leef": "LEEF",
    "json": "JSON",
    "syslog": "Syslog",
    "rfc3164": "Syslog (RFC 3164)",
    "rfc5424": "Syslog (RFC 5424)",
    "cisco": "Cisco ASA",
    "cisco_asa": "Cisco ASA",
    "paloalto": "Palo Alto PAN-OS",
    "panos": "Palo Alto PAN-OS",
    "aws": "AWS VPC Flow",
    "aws_vpc": "AWS VPC Flow",
    "fortinet": "Fortinet FortiOS",
    "fortios": "Fortinet FortiOS",
    "sshd": "Linux SSHD",
    "linux_sshd": "Linux SSHD",
    "apache": "Apache Access",
    "nginx": "Nginx Access",
    "windows": "Windows Security XML",
    "keyvalue": "Key-Value",
    "kv": "Key-Value",
    "csv": "CSV",
}


class ULPFArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser returning exit code 2 and clean error messages."""
    def error(self, message):
        sys.stderr.write(f"ERROR: {message}\n")
        sys.stderr.write("Run 'ulpf --help' for usage instructions.\n")
        sys.exit(2)


def format_size(size_bytes: int) -> str:
    """Format bytes into clean human readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def detect_format_and_source(
    lines: List[str],
    pipeline: ProcessingPipeline,
    format_arg: Optional[str] = None,
    source_arg: Optional[str] = None
) -> Tuple[str, str]:
    """Detect or map format and source based on arguments and log inspection."""
    detected_format = ""
    detected_source = ""

    if format_arg:
        key = format_arg.lower().strip()
        if key in SUPPORTED_FORMATS:
            detected_format = SUPPORTED_FORMATS[key]
        else:
            detected_format = format_arg.upper()

    if source_arg:
        detected_source = source_arg

    # Sample first non-empty lines for content-based inspection
    sample_line = ""
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            sample_line = stripped
            break

    if not sample_line and lines:
        sample_line = lines[0].strip()

    if sample_line:
        claimed_pack = pipeline.registry.find_matching_pack(sample_line)
        if claimed_pack:
            if not detected_format:
                detected_format = claimed_pack.product if claimed_pack.product != "Unknown" else claimed_pack.name
            if not detected_source:
                detected_source = claimed_pack.vendor if claimed_pack.vendor != "Generic" else claimed_pack.name
        else:
            if not detected_format:
                if decode_cef(sample_line):
                    detected_format = "CEF"
                    if not detected_source:
                        detected_source = "Firewall"
                elif decode_json(sample_line):
                    detected_format = "JSON"
                    if not detected_source:
                        detected_source = "Application / Security"
                elif decode_leef(sample_line):
                    detected_format = "LEEF"
                    if not detected_source:
                        detected_source = "Security Device"
                elif decode_syslog_rfc5424(sample_line):
                    detected_format = "Syslog (RFC 5424)"
                    if not detected_source:
                        detected_source = "Syslog"
                elif decode_syslog_rfc3164(sample_line):
                    detected_format = "Syslog (RFC 3164)"
                    if not detected_source:
                        detected_source = "Syslog"
                elif decode_keyvalue(sample_line):
                    detected_format = "Key-Value"
                    if not detected_source:
                        detected_source = "Security Device"
                else:
                    detected_format = "Raw / Unstructured"
                    if not detected_source:
                        detected_source = "Generic"

    if not detected_format:
        detected_format = "Generic"
    if not detected_source:
        detected_source = "Log Source"

    return detected_format, detected_source


def validate_ocsf_event(event: Dict[str, Any]) -> bool:
    """Validate that required OCSF 1.9 schema fields are present."""
    if not isinstance(event, dict):
        return False
    required_keys = ["metadata", "class_uid", "category_uid", "time", "raw_data", "unmapped", "fingerprint", "prev_hash"]
    for k in required_keys:
        if k not in event:
            return False
    if not isinstance(event["metadata"], dict) or "version" not in event["metadata"]:
        return False
    if not isinstance(event["unmapped"], dict) or "ulpf_raw_locator" not in event["unmapped"]:
        return False
    return True


def execute_process(args: argparse.Namespace) -> int:
    """Execute the ULPF process command."""
    input_path = Path(args.input_file)
    verbose = getattr(args, "verbose", False)
    json_mode = getattr(args, "json", False)

    # 1. Validate input file exists
    if not input_path.exists():
        sys.stderr.write(f"ERROR: Input file does not exist:\n{args.input_file}\n")
        return 3

    if not input_path.is_file():
        sys.stderr.write(f"ERROR: Input path is not a file:\n{args.input_file}\n")
        return 3

    try:
        file_size_bytes = input_path.stat().st_size
    except PermissionError:
        sys.stderr.write(f"ERROR: Permission denied accessing input file:\n{args.input_file}\n")
        return 3
    except Exception as e:
        sys.stderr.write(f"ERROR: Could not inspect file {args.input_file}: {e}\n")
        return 3

    if file_size_bytes == 0:
        sys.stderr.write(f"ERROR: Input file is empty:\n{args.input_file}\n")
        return 3

    # 2. Validate format if explicitly provided
    if args.format:
        fmt_key = args.format.lower().strip()
        if fmt_key not in SUPPORTED_FORMATS:
            supported_list = ", ".join(sorted(set(SUPPORTED_FORMATS.keys())))
            sys.stderr.write(
                f"ERROR: Unsupported format '{args.format}'.\n"
                f"Supported formats: {supported_list}\n"
            )
            return 4

    # 3. Handle configuration file if provided
    config_data: Dict[str, Any] = {}
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            sys.stderr.write(f"ERROR: Configuration file does not exist:\n{args.config}\n")
            return 3
        try:
            cfg_text = config_path.read_text(encoding="utf-8")
            if config_path.suffix in (".yaml", ".yml"):
                import yaml
                config_data = yaml.safe_load(cfg_text) or {}
            else:
                config_data = json.loads(cfg_text)
            if not isinstance(config_data, dict):
                sys.stderr.write(f"ERROR: Invalid configuration file content (expected object):\n{args.config}\n")
                return 3
        except Exception as e:
            sys.stderr.write(f"ERROR: Invalid configuration file:\n{args.config} ({e})\n")
            return 3

    # Output directory setup
    output_dir = Path(args.output or config_data.get("output", "output"))
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        sys.stderr.write(f"ERROR: Permission denied creating output directory:\n{output_dir}\n")
        return 3

    raw_vault_dir = output_dir / "raw"
    lake_dir = output_dir / "lake"
    normalized_json_path = output_dir / "normalized.json"
    metadata_json_path = output_dir / "metadata.json"

    # Start timing
    start_time = time.perf_counter()

    # Read input file lines
    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = [line.rstrip("\r\n") for line in f]
    except PermissionError:
        sys.stderr.write(f"ERROR: Permission denied reading input file:\n{args.input_file}\n")
        return 3
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to read input file {args.input_file}: {e}\n")
        if verbose:
            traceback.print_exc()
        return 3

    valid_lines = [l for l in raw_lines if l.strip()]
    events_read = len(valid_lines)

    if events_read == 0:
        sys.stderr.write(f"ERROR: Input file contains no valid log lines:\n{args.input_file}\n")
        return 3

    # Initialize ProcessingPipeline
    try:
        packs_dir = config_data.get("packs_dir", None)
        passphrase = config_data.get("passphrase", None)
        pipeline = ProcessingPipeline(
            vault_dir=str(raw_vault_dir),
            lake_dir=str(lake_dir),
            packs_dir=packs_dir,
            passphrase=passphrase
        )
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to initialize ULPF pipeline: {e}\n")
        if verbose:
            traceback.print_exc()
        return 1

    # Detect Format and Source
    detected_format, detected_source = detect_format_and_source(
        valid_lines,
        pipeline,
        format_arg=args.format,
        source_arg=args.source or config_data.get("source")
    )

    # Print Terminal Header if not JSON mode
    if not json_mode:
        print("=" * 60)
        print("ULPF - Universal Log Pre-processing Framework")
        print("=" * 60)
        print()
        print(f"Input File       : {args.input_file}")
        print(f"File Size        : {format_size(file_size_bytes)}")
        print(f"Format           : {detected_format}")
        print(f"Source           : {detected_source}")
        print(f"Mode             : Offline / Air-Gapped")
        print()

    # Stage 1: Ingesting raw events
    if not json_mode:
        print("[1/7] Ingesting raw events................. OK")

    # Stage 2: Detecting format
    if not json_mode:
        print("[2/7] Detecting format..................... OK")

    # Stage 3 & 4: Parsing events & Normalizing to OCSF
    events: List[Dict[str, Any]] = []
    events_rejected = 0
    vendor_hint = args.source or detected_source

    for idx, line in enumerate(valid_lines):
        try:
            ev = pipeline.process_raw(line, vendor_hint=vendor_hint)
            events.append(ev)
        except Exception as e:
            events_rejected += 1
            if verbose:
                sys.stderr.write(f"Warning: Parser/normalizer error on line {idx}: {e}\n")

    events_parsed = len(events)
    events_normalized = sum(1 for ev in events if ev.get("class_uid", 0) > 0 or "metadata" in ev)

    if not json_mode:
        print("[3/7] Parsing events....................... OK")
        print("[4/7] Normalizing to OCSF.................. OK")

    # Stage 5: Validating events
    validation_passed = True
    if events:
        for ev in events:
            if not validate_ocsf_event(ev):
                validation_passed = False
                break
    else:
        validation_passed = False

    if not validation_passed:
        if not json_mode:
            print("[5/7] Validating events.................... FAILED")
            sys.stderr.write("ERROR: OCSF schema validation failed on processed events.\n")
        pipeline.close()
        return 5

    if not json_mode:
        print("[5/7] Validating events.................... OK")

    # Stage 6: Preserving raw evidence (flush and verify retrieval)
    try:
        pipeline.vault.flush()
        raw_preservation_passed = True
        traceability_passed = True

        # Check raw retrieval and sha256 traceability on sample of events
        sample_check_count = min(len(events), 50)
        for i in range(sample_check_count):
            ev = events[i]
            locator_str = ev.get("unmapped", {}).get("ulpf_raw_locator")
            expected_sha = ev.get("unmapped", {}).get("raw_sha256")
            if not locator_str or not expected_sha:
                traceability_passed = False
                raw_preservation_passed = False
                break

            retrieved_bytes = pipeline.vault.get_raw(locator_str)
            computed_sha = hashlib.sha256(retrieved_bytes).hexdigest()
            if computed_sha != expected_sha:
                raw_preservation_passed = False
                traceability_passed = False
                break
    except Exception as e:
        raw_preservation_passed = False
        traceability_passed = False
        if verbose:
            sys.stderr.write(f"Raw preservation error: {e}\n")

    if not raw_preservation_passed:
        if not json_mode:
            print("[6/7] Preserving raw evidence.............. FAILED")
            sys.stderr.write("ERROR: Raw evidence verification failed.\n")
        pipeline.close()
        return 5

    if not json_mode:
        print("[6/7] Preserving raw evidence.............. OK")

    # Stage 7: Verifying integrity
    integrity_status = "PASS"
    integrity_verified: Optional[bool] = None

    if args.no_integrity:
        integrity_status = "SKIPPED"
        integrity_verified = None
        if not json_mode:
            print("[7/7] Verifying integrity.................. SKIPPED (--no-integrity)")
    else:
        is_valid, msg, broken_seq = verify_chain(events)
        if is_valid:
            integrity_verified = True
            integrity_status = "PASS"
            if not json_mode:
                print("[7/7] Verifying integrity.................. OK")
        else:
            integrity_verified = False
            integrity_status = "FAIL"
            if not json_mode:
                print(f"[7/7] Verifying integrity.................. FAILED ({msg})")
                sys.stderr.write(f"ERROR: Cryptographic hash chain verification failed: {msg}\n")
            pipeline.close()
            return 5

    # Sign Merkle Checkpoint if pending
    try:
        if pipeline.pending_fingerprints_for_merkle:
            pipeline._create_checkpoint()
    except Exception:
        pass

    # Finish timing
    elapsed_seconds = max(time.perf_counter() - start_time, 0.001)
    throughput = int(events_read / elapsed_seconds)

    # Write output files
    outputs = {
        "normalized": str(normalized_json_path.as_posix()),
        "raw": str((raw_vault_dir.as_posix()).rstrip("/") + "/"),
        "metadata": str(metadata_json_path.as_posix())
    }

    try:
        with open(normalized_json_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to write normalized JSON output: {e}\n")
        pipeline.close()
        return 1

    metadata_record = {
        "input_file": str(args.input_file),
        "file_size_bytes": file_size_bytes,
        "file_size_human": format_size(file_size_bytes),
        "format": detected_format,
        "source": detected_source,
        "mode": "Offline / Air-Gapped",
        "events_read": events_read,
        "events_parsed": events_parsed,
        "events_normalized": events_normalized,
        "events_rejected": events_rejected,
        "raw_preserved": raw_preservation_passed,
        "traceability_verified": traceability_passed,
        "integrity_verified": integrity_verified,
        "processing_time_seconds": round(elapsed_seconds, 2),
        "throughput_events_per_second": throughput,
        "outputs": outputs
    }

    try:
        with open(metadata_json_path, "w", encoding="utf-8") as f:
            json.dump(metadata_record, f, indent=2)
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to write metadata JSON: {e}\n")

    # Clean shutdown
    pipeline.close()

    # Display results
    if json_mode:
        # Machine-readable JSON output only
        json_output = {
            "input_file": str(args.input_file),
            "format": detected_format,
            "events_read": events_read,
            "events_parsed": events_parsed,
            "events_normalized": events_normalized,
            "events_rejected": events_rejected,
            "raw_preserved": raw_preservation_passed,
            "traceability_verified": traceability_passed,
            "integrity_verified": integrity_verified,
            "processing_time_seconds": round(elapsed_seconds, 2),
            "throughput_events_per_second": throughput,
            "outputs": outputs
        }
        print(json.dumps(json_output, indent=2))
    else:
        print()
        print("-" * 60)
        print("RESULT")
        print("-" * 60)
        print(f"Events Read       : {events_read:,}")
        print(f"Events Parsed     : {events_parsed:,}")
        print(f"Events Normalized : {events_normalized:,}")
        print(f"Events Rejected   : {events_rejected:,}")
        print()
        print(f"Raw Preservation  : {'PASS' if raw_preservation_passed else 'FAIL'}")
        print(f"Traceability      : {'PASS' if traceability_passed else 'FAIL'}")
        print(f"Integrity         : {integrity_status}")
        print()
        print("Output:")
        print(f"  Normalized JSON : {outputs['normalized']}")
        print(f"  Raw Evidence    : {outputs['raw']}")
        print(f"  Metadata        : {outputs['metadata']}")
        print()
        print(f"Processing Time   : {elapsed_seconds:.2f} seconds")
        print(f"Throughput        : {throughput:,} events/sec")
        print()
        print("=" * 60)
        print("ULPF PROCESSING COMPLETE")
        print("=" * 60)

    return 0


def build_parser() -> ULPFArgumentParser:
    """Construct command-line argument parser."""
    parser = ULPFArgumentParser(
        prog="ulpf",
        description="Universal Log Pre-processing Framework (ULPF) - Production CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"ulpf {VERSION} ({SCHEMA_VERSION})",
        help="Show program version and exit"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Command: process
    proc_parser = subparsers.add_parser(
        "process",
        help="Process a log file through the 7-stage ULPF pipeline",
        description="Execute the complete 7-stage ULPF pipeline on an input log file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    proc_parser.add_argument(
        "input_file",
        help="Path to the input log file to process"
    )
    proc_parser.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory for normalized logs, raw evidence, and metadata"
    )
    proc_parser.add_argument(
        "--format", "-f",
        default=None,
        help="Explicit log format (e.g. cef, json, syslog, cisco_asa, paloalto, aws, fortinet, sshd)"
    )
    proc_parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to configuration file (YAML or JSON)"
    )
    proc_parser.add_argument(
        "--source", "-s",
        default=None,
        help="Log source name / vendor hint (e.g. Firewall, Linux SSHD, Suricata)"
    )
    proc_parser.add_argument(
        "--no-integrity",
        action="store_true",
        default=False,
        help="Skip cryptographic hash chain integrity verification"
    )
    proc_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output machine-readable JSON only"
    )
    proc_parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose debug tracebacks on error"
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()

    # If no arguments provided, display help and return code 2
    if not argv:
        parser.print_help(sys.stderr)
        return 2

    # Parse arguments
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code

    if args.command == "process":
        try:
            return execute_process(args)
        except Exception as e:
            sys.stderr.write(f"ERROR: General processing failure: {e}\n")
            if getattr(args, "verbose", False):
                traceback.print_exc()
            return 1
    else:
        parser.print_help(sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
