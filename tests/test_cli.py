"""
Unit and integration tests for ULPF Command Line Interface (CLI)
Team LunarX - SIH26156 (NTRO)
"""

import sys
import json
import pytest
from pathlib import Path
from core.cli import main, build_parser


def test_cli_version():
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0


def test_cli_help():
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0


def test_cli_no_args():
    code = main([])
    assert code == 2


def test_cli_process_firewall_sample(tmp_path):
    output_dir = tmp_path / "cli_out"
    code = main([
        "process",
        "samples/firewall.log",
        "--output", str(output_dir)
    ])
    assert code == 0
    assert (output_dir / "normalized.json").exists()
    assert (output_dir / "metadata.json").exists()
    assert (output_dir / "raw").exists()

    meta = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert meta["events_read"] == 5
    assert meta["events_parsed"] == 5
    assert meta["raw_preserved"] is True
    assert meta["traceability_verified"] is True
    assert meta["integrity_verified"] is True


def test_cli_process_json_mode(tmp_path, capsys):
    output_dir = tmp_path / "cli_json_out"
    code = main([
        "process",
        "samples/firewall.log",
        "--output", str(output_dir),
        "--json"
    ])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["input_file"] == "samples/firewall.log"
    assert data["format"] == "CEF"
    assert data["events_read"] == 5
    assert data["raw_preserved"] is True
    assert data["integrity_verified"] is True


def test_cli_missing_input_file(capsys):
    code = main(["process", "non_existent_file.log"])
    assert code == 3
    captured = capsys.readouterr()
    assert "ERROR: Input file does not exist:" in captured.err


def test_cli_unsupported_format(capsys):
    code = main(["process", "samples/firewall.log", "--format", "unsupported_xyz_format"])
    assert code == 4
    captured = capsys.readouterr()
    assert "ERROR: Unsupported format" in captured.err


def test_cli_no_integrity(tmp_path):
    output_dir = tmp_path / "cli_no_integrity"
    code = main([
        "process",
        "samples/firewall.log",
        "--output", str(output_dir),
        "--no-integrity"
    ])
    assert code == 0
    meta = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert meta["integrity_verified"] is None
