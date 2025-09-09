#!/usr/bin/env python3
"""
Multi-Factor IDS Setup Script
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_requirements():
    """Check system requirements"""
    print("Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher required")
        return False
    
    # Check for required system packages
    required_packages = ['tcpdump', 'nmap']
    for package in required_packages:
        if shutil.which(package) is None:
            print(f"Warning: {package} not found. Some features may not work.")
    
    return True

def create_directories():
    """Create necessary directories"""
    print("Creating directory structure...")
    
    directories = [
        'data/logs',
        'data/baselines',
        'data/alerts',
        'data/signatures',
        'logs',
        'temp'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  Created: {directory}")

def install_dependencies():
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            '-r', 'requirements/base.txt'
        ], check=True)
        print("  Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False
    
    return True

def setup_configuration():
    """Setup configuration files"""
    print("Setting up configuration...")
    
    config_file = Path('config/config.yaml')
    if not config_file.exists():
        shutil.copy('config/config.example.yaml', config_file)
        print("  Created config/config.yaml from template")
        print("  Please edit config/config.yaml with your settings")
    else:
        print("  config/config.yaml already exists")

def initialize_database():
    """Initialize database schema"""
    print("Initializing database...")
    # This will be implemented when we create the database modules
    print("  Database initialization will be completed in the next phase")

def main():
    """Main setup function"""
    print("Multi-Factor IDS Setup")
    print("=" * 50)
    
    if not check_requirements():
        sys.exit(1)
    
    create_directories()
    
    if not install_dependencies():
        sys.exit(1)
    
    setup_configuration()
    initialize_database()
    
    print("\nSetup completed successfully!")
    print("Next steps:")
    print("1. Edit config/config.yaml with your settings")
    print("2. Run 'docker-compose up -d' to start services")
    print("3. Run 'python src/main.py' to start the IDS")

if __name__ == '__main__':
    main()