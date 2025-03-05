#!/usr/bin/env python3
"""
Debug script for the Gateway Router application.
This script helps diagnose startup issues.
"""

import sys
import socket
import traceback

def test_port_binding(port):
    """Test if we can bind to the specified port."""
    print(f"Testing port binding on port {port}...")
    
    try:
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set option to reuse address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to the port
        s.bind(('0.0.0.0', port))
        # Listen
        s.listen(5)
        
        print(f"Successfully bound to port {port}")
        s.close()
        return True
    except Exception as e:
        print(f"Error binding to port {port}: {e}")
        print(traceback.format_exc())
        return False

def main():
    """Main entry point for the debug script."""
    print("Gateway Router Debug Script")
    print("=========================")
    
    # Test port binding
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port number: {sys.argv[1]}, using default port 8080")
    
    test_port_binding(port)
    
    # Try importing required modules
    print("\nTesting module imports:")
    modules = [
        'requests',
        'oracledb',
        'configparser',
        'http.server',
        'uuid',
        'logging'
    ]
    
    for module in modules:
        try:
            __import__(module)
            print(f"  ✓ Successfully imported {module}")
        except ImportError as e:
            print(f"  ✗ Failed to import {module}: {e}")

if __name__ == "__main__":
    main()