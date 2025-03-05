#!/usr/bin/env python3
"""
Direct API Client Test

A simple script to test direct API access to the target endpoint.
This helps in comparing the response from the direct API call with the proxy.
"""

import requests
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DirectAPIClient')

def test_direct_api():
    """Test direct API access to the target endpoint."""
    # Target URL - same as the one in your gateway router
    target_url = "https://api.restful-api.dev/objects"
    
    # Headers - similar to what your gateway router might use
    headers = {
        'User-Agent': 'DirectAPIClient/1.0',
        'Accept': '*/*'
    }
    
    logger.info(f"Making direct GET request to {target_url}")
    
    try:
        # Make the request
        response = requests.get(
            url=target_url,
            headers=headers,
            timeout=30
        )
        
        # Log response details
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {dict(response.headers)}")
        logger.info(f"Response content length: {len(response.content) if response.content else 0} bytes")
        
        # Try to parse JSON if the response is JSON
        if 'application/json' in response.headers.get('Content-Type', '').lower():
            try:
                json_data = response.json()
                logger.info(f"Parsed JSON data (first 2 items): {json.dumps(json_data[:2] if isinstance(json_data, list) and len(json_data) > 2 else json_data, indent=2)}")
                logger.info(f"Total JSON items: {len(json_data) if isinstance(json_data, list) else 'Not a list'}")
            except Exception as e:
                logger.error(f"Error parsing JSON: {str(e)}")
                logger.info(f"Raw response text: {response.text[:500]}...")
        else:
            logger.info(f"Response is not JSON. Content preview: {response.text[:500]}...")
            
    except Exception as e:
        logger.error(f"Error making direct API request: {str(e)}")

if __name__ == "__main__":
    test_direct_api()