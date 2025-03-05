"""
Sample hooks for the Gateway Router.

This file provides sample hook implementations that can be used with the Gateway Router.
Customize these hooks to implement your specific behavior.
"""

import logging
import json
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger('GatewayRouter.Hooks')

def pre_request(headers: Dict[str, str], trace_id: str, target_url: str) -> Dict[str, str]:
    """
    Hook that executes before a request is sent to the target server.
    
    Args:
        headers: The request headers
        trace_id: The trace ID for the request
        target_url: The target URL
        
    Returns:
        Modified headers
    """
    # Add custom headers
    headers['X-Custom-Header'] = 'Value'
    
    # You can perform additional logic based on the target URL
    if 'api' in target_url:
        headers['X-API-Version'] = '1.0'
    
    logger.debug(f"[{trace_id}] pre_request hook executed for {target_url}")
    return headers


def post_request(response: requests.Response, trace_id: str, target_url: str) -> requests.Response:
    """
    Hook that executes after a request is sent to the target server but before sending the response back.
    
    Args:
        response: The response from the target server
        trace_id: The trace ID for the request
        target_url: The target URL
        
    Returns:
        Modified response
    """
    # You can modify the response object here if needed
    logger.debug(f"[{trace_id}] post_request hook executed for {target_url}, status: {response.status_code}")
    
    # Example: Add timing information
    response.headers['X-Response-Time'] = '10ms'  # This would be dynamic in a real implementation
    
    return response


def pre_response(headers: Dict[str, str], trace_id: str, target_url: str) -> Dict[str, str]:
    """
    Hook that executes before sending the response back to the client.
    
    Args:
        headers: The response headers
        trace_id: The trace ID for the request
        target_url: The target URL
        
    Returns:
        Modified headers
    """
    # Add or modify response headers
    headers['X-Gateway-Processed'] = 'true'
    
    # Remove sensitive headers if needed
    if 'X-Internal-Token' in headers:
        del headers['X-Internal-Token']
    
    logger.debug(f"[{trace_id}] pre_response hook executed for {target_url}")
    return headers


def post_response(
    response_data: Optional[Any], 
    trace_id: str, 
    target_url: str, 
    status_code: int
) -> None:
    """
    Hook that executes after the response is sent back to the client.
    
    Args:
        response_data: The response data or None
        trace_id: The trace ID for the request
        target_url: The target URL
        status_code: The HTTP status code
        
    Returns:
        None
    """
    # This hook is typically used for logging or metrics
    logger.debug(f"[{trace_id}] post_response hook executed for {target_url}, status: {status_code}")
    
    # Example: You could send metrics to a monitoring system here
    # send_metrics(trace_id, target_url, status_code)


# Example of a hook that modifies the response body
def modify_response_body(response: requests.Response, trace_id: str, target_url: str) -> requests.Response:
    """
    Example hook that modifies the response body.
    
    Args:
        response: The response from the target server
        trace_id: The trace ID for the request
        target_url: The target URL
        
    Returns:
        Modified response
    """
    # Only process JSON responses
    if 'application/json' in response.headers.get('Content-Type', ''):
        try:
            # Get the response content
            data = response.json()
            
            # Modify the data
            if isinstance(data, dict):
                # Add gateway info
                data['_gateway'] = {
                    'trace_id': trace_id,
                    'processed_time': '2023-01-01T12:00:00Z'  # This would be dynamic
                }
                
                # Create a new response with the modified data
                new_response = requests.Response()
                new_response.status_code = response.status_code
                new_response.headers = response.headers
                
                # Set the new content
                new_content = json.dumps(data).encode('utf-8')
                new_response.headers['Content-Length'] = str(len(new_content))
                
                # Override the response object's content with our modified version
                # This is a bit of a hack but works for demonstration
                new_response._content = new_content
                
                return new_response
        except Exception as e:
            logger.error(f"[{trace_id}] Error modifying response body: {e}")
    
    # Return original response if not modified
    return response