#!/usr/bin/env python3
"""
Packaging script for the Gateway Router application.
Creates standalone executables for Windows and Linux.
"""

import os
import sys
import platform
import subprocess

def run_command(command):
    """Run a shell command and print the output."""
    print(f"Running: {' '.join(command)}")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    for line in process.stdout:
        print(line.strip())
    
    process.wait()
    if process.returncode != 0:
        print(f"Command failed with exit code {process.returncode}")
        sys.exit(process.returncode)

def install_dependencies():
    """Install required dependencies for packaging."""
    run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    run_command([sys.executable, "-m", "pip", "install", "pyinstaller"])
    run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def create_package():
    """Create the standalone executable package."""
    # Create the spec file with proper imports
    spec_content = """
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['gateway_router.py'],
    pathex=[],
    binaries=[],
    datas=[('config.ini', '.')],
    hiddenimports=['oracledb', 'hooks'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='gateway_router',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
    
    with open("gateway_router.spec", "w") as f:
        f.write(spec_content)
    
    # Run PyInstaller with the spec file
    run_command(["pyinstaller", "gateway_router.spec", "--clean"])

def copy_additional_files():
    """Copy additional files to the dist directory."""
    dist_dir = "dist"
    
    # Copy README.md
    if os.path.exists("README.md"):
        run_command(["cp", "README.md", dist_dir])
    
    # Copy sample config and hooks
    if os.path.exists("config.ini"):
        run_command(["cp", "config.ini", dist_dir])
    
    if os.path.exists("hooks.py"):
        run_command(["cp", "hooks.py", dist_dir])

def create_zip_archive():
    """Create a zip archive of the package."""
    system = platform.system().lower()
    dist_dir = "dist"
    
    if system == "windows":
        archive_name = "gateway_router_windows.zip"
        run_command(["powershell", "Compress-Archive", "-Path", f"{dist_dir}/*", "-DestinationPath", archive_name])
    else:
        archive_name = "gateway_router_linux.tar.gz"
        run_command(["tar", "-czvf", archive_name, "-C", dist_dir, "."])
    
    print(f"Created archive: {archive_name}")

def main():
    """Main entry point."""
    # Ensure we're in the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    print("Starting packaging process...")
    install_dependencies()
    create_package()
    copy_additional_files()
    create_zip_archive()
    print("Packaging completed successfully.")

if __name__ == "__main__":
    main()