# Gateway Routing Application

A Python-based gateway routing application that routes incoming requests to different backend servers based on URL patterns stored in an Oracle database.

## Features

- URL-based routing to different backend servers
- Oracle database integration for routing configuration
- Header preservation during request forwarding
- Request/response hooks for customization
- Trace ID generation for request tracking across servers
- Comprehensive logging
- Support for response modification
- Cross-platform (Windows/Linux) compatibility
- Plug-and-play deployment

## Requirements

- Python 3.6 or higher
- Oracle client libraries (if not using the standalone package)

## Installation

### Using the packaged version (recommended)

Download the latest release package and extract it:

```bash
# Linux
./gateway_router --port 8080

# Windows
gateway_router.exe --port 8080