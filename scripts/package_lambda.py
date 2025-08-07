#!/usr/bin/env python3
"""
Lambda packaging script for the refactored honeypot system.

This script creates deployment packages for the modular honeypot codebase,
replacing the old monolithic packaging approach.
"""

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


def create_lambda_package(source_dir: str, output_file: str, handler_file: str = "lambda_handler.py") -> None:
    """
    Create a Lambda deployment package from the modular source code.
    
    Args:
        source_dir: Directory containing the source code
        output_file: Output zip file path
        handler_file: Main handler file to use as entry point
    """
    print(f"📦 Creating Lambda package: {output_file}")
    
    # Create temporary directory for packaging
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Copy source code
        src_path = Path(source_dir)
        if src_path.exists():
            shutil.copytree(src_path, temp_path / "src")
            print(f"✅ Copied source code from {src_path}")
        else:
            raise FileNotFoundError(f"Source directory not found: {src_path}")
        
        # Create the main handler file that imports from src
        handler_content = f'''"""
AWS Lambda handler for the refactored honeypot system.
This file provides backward compatibility with the original handler name.
"""

from src.lambda_handler import lambda_handler as honeypot_lambda_handler

# Main handler function (backward compatible)
def lambda_handler(event, context):
    """Main Lambda handler - delegates to the modular implementation."""
    return honeypot_lambda_handler(event, context)

# Alternative handler names for compatibility
honeypot_lambda = lambda_handler
'''
        
        # Write the handler file
        handler_path = temp_path / handler_file
        handler_path.write_text(handler_content)
        print(f"✅ Created handler file: {handler_file}")
        
        # Create the zip package
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add all files from temp directory
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    # Calculate relative path for zip
                    arc_name = file_path.relative_to(temp_path)
                    zip_file.write(file_path, arc_name)
                    print(f"   Added: {arc_name}")
        
        print(f"✅ Package created successfully: {output_file}")
        
        # Show package info
        with zipfile.ZipFile(output_file, 'r') as zip_file:
            file_count = len(zip_file.namelist())
            package_size = os.path.getsize(output_file)
            print(f"📊 Package info: {file_count} files, {package_size:,} bytes")


def main():
    """Main packaging function."""
    print("🍯 Honeypot Lambda Packaging Script")
    print("=" * 50)
    
    # Define paths
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    src_dir = repo_root / "src"
    
    # Create packages for different deployment targets
    packages = [
        {
            "name": "honeypot_lambda.zip",
            "handler": "honeypot_lambda.py",
            "description": "Main honeypot package (backward compatible)"
        },
        {
            "name": "lambda_function.zip", 
            "handler": "lambda_function.py",
            "description": "Alternative package name"
        }
    ]
    
    try:
        for package in packages:
            output_path = repo_root / package["name"]
            print(f"\n🔨 Building {package['description']}")
            create_lambda_package(
                source_dir=str(src_dir),
                output_file=str(output_path),
                handler_file=package["handler"]
            )
        
        print("\n🎉 All packages created successfully!")
        print("\n📋 Next steps:")
        print("1. Test the packages locally")
        print("2. Deploy with: terraform apply")
        print("3. Verify the new modular system is working")
        print("4. Remove old monolithic files")
        
    except Exception as e:
        print(f"❌ Error creating packages: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())