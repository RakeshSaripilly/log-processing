# PowerShell build script for ULPF Hybrid Rust Core
$ErrorActionPreference = "Stop"
Write-Host "Building ULPF Hybrid Rust Core (rust_core)..." -ForegroundColor Cyan
python -m pip install maturin
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY = "1"
if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = "$env:TEMP\cargo_ulpf"
}
$env:Path += ";$env:USERPROFILE\.cargo\bin"
python -m maturin build --release --manifest-path rust_core/Cargo.toml --interpreter python
$wheel = (Get-ChildItem "$env:CARGO_TARGET_DIR\wheels\ulpf_core_rs-*.whl" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
python -m pip install --force-reinstall $wheel
Write-Host "ULPF Rust Core successfully installed!" -ForegroundColor Green
