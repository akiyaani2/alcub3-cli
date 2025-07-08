#!/usr/bin/env python3
"""
ALCUB3 Demo Setup Script
Prepares the environment for running the PKI/CAC demo
"""

import sys
import os
import subprocess

def install_colorama():
    """Install colorama for better visual presentation."""
    try:
        import colorama
        print("✅ colorama already installed")
        return True
    except ImportError:
        print("📦 Installing colorama for enhanced demo visuals...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
            print("✅ colorama installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("⚠️  Could not install colorama - demo will run without colors")
            return False

def check_python_version():
    """Check Python version compatibility."""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.7+")
        return False

def main():
    """Setup the demo environment."""
    print("🔧 ALCUB3 Demo Environment Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        print("\n❌ Setup failed - please upgrade Python")
        return False
    
    # Install optional dependencies
    install_colorama()
    
    # Check demo file exists
    script_dir = os.path.dirname(__file__)
    demo_file = os.path.join(script_dir, "demo_clearance_system.py")
    if os.path.exists(demo_file):
        print(f"✅ Demo file found: {os.path.basename(demo_file)}")
    else:
        print(f"❌ Demo file missing: {demo_file}")
        return False
    
    print("\n🎉 Setup complete!")
    print(f"\n🚀 To run the demo:")
    print(f"   python3 {demo_file}")
    print(f"   OR (with scripted mode): python3 {demo_file} --scripted script_commands.txt")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)