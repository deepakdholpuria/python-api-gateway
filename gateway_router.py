#!/usr/bin/env python3
"""
Gateway Router Application

A Python-based gateway routing application that routes incoming requests
to different backend servers based on URL patterns stored in an Oracle database.
"""

import argparse
import logging
import uuid
import os
import sys
import json
from typing import Dict, Any, Optional, List
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
import oracledb
import configparser
from urllib.parse import urlparse
import socket
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('gateway_router.log')
    ]
)
logger = logging.getLogger('GatewayRouter')

class Configuration:
    """Configuration manager for the gateway router application."""
    
    def __init__(self, config_file: str = 'config.ini'):
        """Initialize the configuration from a config file."""
        self.config = configparser.ConfigParser()
        
        if not os.path.exists(config_file):
            # Create default config if it doesn't exist
            self._create_default_config(config_file)
        
        self.config.read(config_file)
        
    def _create_default_config(self, config_file: str):
        """Create a default configuration file."""
        self.config['DATABASE'] = {
            'connection_string': 'user/password@hostname:port/service_name',
            'min_connections': '1',
            'max_connections': '5',
            'pool_increment': '1'
        }
        
        self.config['SERVER'] = {
            'host': '0.0.0.0',
            'port': '8080'
        }
        
        self.config['SERVERS'] = {
            'OBPM': 'http://obpm-server.example.com',
            'HOST': 'http://host-server.example.com',
            'OBRH': 'http://obrh-server.example.com'
        }
        
        self.config['HOOKS'] = {
            'pre_request': 'hooks.pre_request',
            'post_request': 'hooks.post_request',
            'pre_response': 'hooks.pre_response',
            'post_response': 'hooks.post_response'
        }
        
        # Write the configuration to file
        with open(config_file, 'w') as f:
            self.config.write(f)
            
    def get_db_config(self) -> Dict[str, Any]:
        """Get database configuration."""
        return {
            'connection_string': self.config.get('DATABASE', 'connection_string'),
            'min_connections': self.config.getint('DATABASE', 'min_connections', fallback=1),
            'max_connections': self.config.getint('DATABASE', 'max_connections', fallback=5),
            'pool_increment': self.config.getint('DATABASE', 'pool_increment', fallback=1)
        }
    
    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration."""
        return {
            'host': self.config.get('SERVER', 'host', fallback='0.0.0.0'),
            'port': self.config.getint('SERVER', 'port', fallback=8080)
        }
        
    def get_servers_mapping(self) -> Dict[str, str]:
        """Get server name to URL mappings."""
        if 'SERVERS' not in self.config:
            return {}
        return dict(self.config['SERVERS'])
    
    def get_hooks_config(self) -> Dict[str, str]:
        """Get hooks configuration."""
        if 'HOOKS' not in self.config:
            return {}
        return dict(self.config['HOOKS'])


class DatabaseManager:
    """Manager for database operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the database manager with configuration."""
        self.connection_string = config['connection_string']
        self.min_connections = config['min_connections']
        self.max_connections = config['max_connections']
        self.pool_increment = config['pool_increment']
        self.pool = None
        
    def initialize(self):
        """Initialize the connection pool."""
        try:
            self.pool = oracledb.create_pool(
                dsn=self.connection_string,
                min=self.min_connections,
                max=self.max_connections,
                increment=self.pool_increment
            )
            logger.info("Database connection pool initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            raise
    
    def get_routes(self) -> List[Dict[str, str]]:
        """
        Fetch routing information from the database.
        
        Returns:
            List of dictionaries with 'full_url' and 'replaced_variables' keys.
        """
        if not self.pool:
            raise Exception("Database connection pool not initialized")
        
        routes = []
        query = "SELECT full_url, replaced_variables FROM gateway_routes WHERE is_active = 1"
        
        try:
            with self.pool.acquire() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(query)
                    for row in cursor:
                        routes.append({
                            'full_url': row[0],
                            'replaced_variables': row[1]
                        })
            logger.info(f"Fetched {len(routes)} routes from database")
            return routes
        except Exception as e:
            logger.error(f"Error fetching routes from database: {e}")
            raise
    
    def close(self):
        """Close the database connection pool."""
        if self.pool:
            self.pool.close()
            logger.info("Database connection pool closed")


class RouteManager:
    """Manager for handling routing logic."""
    
    def __init__(self, db_manager: DatabaseManager, servers_mapping: Dict[str, str]):
        """Initialize the route manager with a database manager and servers mapping."""
        self.db_manager = db_manager
        self.servers_mapping = servers_mapping
        self.routes_cache = []
        self.refresh_routes()
        
    def refresh_routes(self):
        """Refresh the routes from the database."""
        try:
            self.routes_cache = self.db_manager.get_routes()
            logger.info("Routes refreshed from database")
        except Exception as e:
            logger.error(f"Failed to refresh routes: {e}")
            if not self.routes_cache:
                raise  # Only raise if we don't have any cached routes
    
    def find_route(self, url: str) -> Optional[Dict[str, str]]:
        """
        Find a matching route for the given URL.
        
        Args:
            url: The URL to match
            
        Returns:
            A dictionary with route information if found, None otherwise
        """
        parsed_url = urlparse(url)
        path_with_query = parsed_url.path
        if parsed_url.query:
            path_with_query += f"?{parsed_url.query}"
        
        for route in self.routes_cache:
            route_parsed = urlparse(route['full_url'])
            route_path_with_query = route_parsed.path
            if route_parsed.query:
                route_path_with_query += f"?{route_parsed.query}"
            
            # Match the path (after host:port)
            if path_with_query == route_path_with_query:
                logger.info(f"Found matching route for {url}: {route['full_url']}")
                return route
        
        logger.warning(f"No matching route found for {url}")
        return None
    
    def get_target_server(self, route: Dict[str, str]) -> Optional[str]:
        """
        Get the target server for a route.
        
        Args:
            route: The route information
            
        Returns:
            The target server URL if available, None otherwise
        """
        server_var = route['replaced_variables']
        if server_var in self.servers_mapping:
            target = self.servers_mapping[server_var]
            logger.info(f"Resolved target server for {server_var}: {target}")
            return target
        
        logger.warning(f"No target server defined for {server_var}")
        return None
    
    def build_target_url(self, original_url: str, route: Dict[str, str], target_server: str) -> str:
        """
        Build the target URL by replacing the host with the target server.
        
        Args:
            original_url: The original URL
            route: The route information
            target_server: The target server URL
            
        Returns:
            The target URL
        """
        original_parsed = urlparse(original_url)
        target_parsed = urlparse(target_server)
        
        # Build the target URL by preserving the path and query
        target_url = f"{target_parsed.scheme}://{target_parsed.netloc}{original_parsed.path}"
        if original_parsed.query:
            target_url += f"?{original_parsed.query}"
        
        logger.info(f"Built target URL: {target_url}")
        return target_url


class HookManager:
    """Manager for handling request/response hooks."""
    
    def __init__(self, hooks_config: Dict[str, str]):
        """Initialize the hook manager with hook configuration."""
        self.hooks = {}
        self._load_hooks(hooks_config)
    
    def _load_hooks(self, hooks_config: Dict[str, str]):
        """Load hooks from configuration."""
        for hook_name, hook_path in hooks_config.items():
            try:
                if hook_path:
                    module_path, function_name = hook_path.rsplit('.', 1)
                    module = __import__(module_path, fromlist=[function_name])
                    self.hooks[hook_name] = getattr(module, function_name)
                    logger.info(f"Loaded hook {hook_name} from {hook_path}")
            except (ImportError, AttributeError, ValueError) as e:
                logger.warning(f"Failed to load hook {hook_name} from {hook_path}: {e}")
    
    def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        """
        Execute a hook if it exists.
        
        Args:
            hook_name: The name of the hook to execute
            args: Positional arguments to pass to the hook
            kwargs: Keyword arguments to pass to the hook
            
        Returns:
            The result of the hook execution
        """
        if hook_name in self.hooks and callable(self.hooks[hook_name]):
            try:
                result = self.hooks[hook_name](*args, **kwargs)
                logger.debug(f"Executed hook {hook_name}")
                return result
            except Exception as e:
                logger.error(f"Error executing hook {hook_name}: {e}")
        
        # Return the first argument unchanged if no hook or error
        return args[0] if args else None


class RequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the gateway router."""
    
    def __init__(self, *args, route_manager=None, hook_manager=None, **kwargs):
        self.route_manager = route_manager
        self.hook_manager = hook_manager
        super().__init__(*args, **kwargs)
    
    def _set_response(self, status_code=200, headers=None):
        """Set the response status code and headers."""
        self.send_response(status_code)
        if headers:
            for header, value in headers.items():
                self.send_header(header, value)
        self.end_headers()
    
    def _get_request_body(self) -> bytes:
        """Get the request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(content_length)
    
    def _get_request_headers(self) -> Dict[str, str]:
        """Get request headers as a dictionary."""
        return dict(self.headers.items())
    
    def _build_request_url(self) -> str:
        """Build the full request URL."""
        host = self.headers.get('Host', 'localhost')
        scheme = 'https' if self.server.socket.family == socket.AF_INET6 else 'http'
        return f"{scheme}://{host}{self.path}"
    
    def _generate_trace_id(self) -> str:
        """Generate a unique trace ID for request tracing."""
        return str(uuid.uuid4())
    
    def _proxy_request(self, method: str):
        """
        Proxy the request to the appropriate server.
        
        Args:
            method: The HTTP method
        """
        trace_id = self._generate_trace_id()
        request_start_time = time.time()
        request_url = self._build_request_url()
        request_headers = self._get_request_headers()
        request_body = self._get_request_body()
        
        # Add tracing ID to headers
        request_headers['X-Gateway-Trace-ID'] = trace_id
        
        # Log incoming request
        logger.info(f"[{trace_id}] Incoming {method} request to {request_url}")
        logger.debug(f"[{trace_id}] Headers: {request_headers}")
        if request_body:
            logger.debug(f"[{trace_id}] Body: {request_body[:1000]}...")
        
        # Find route
        route = self.route_manager.find_route(request_url)
        if not route:
            self._set_response(404)
            self.wfile.write(b"No matching route found")
            logger.warning(f"[{trace_id}] No matching route found for {request_url}")
            return
        
        # Get target server
        target_server = self.route_manager.get_target_server(route)
        if not target_server:
            self._set_response(500)
            self.wfile.write(b"No target server defined for route")
            logger.error(f"[{trace_id}] No target server defined for route")
            return
        
        # Build target URL
        target_url = self.route_manager.build_target_url(request_url, route, target_server)
        
        # Execute pre-request hook
        modified_headers = self.hook_manager.execute_hook('pre_request', request_headers, trace_id, target_url)
        if modified_headers and isinstance(modified_headers, dict):
            request_headers = modified_headers
        
        # Create request to target server
        try:
            # Filter out headers that should not be forwarded
            headers_to_remove = ['Host', 'Content-Length']
            filtered_headers = {k: v for k, v in request_headers.items() if k not in headers_to_remove}
            
            logger.info(f"[{trace_id}] Proxying {method} request to {target_url}")
            
            # Execute request to target server
            response = requests.request(
                method=method,
                url=target_url,
                headers=filtered_headers,
                data=request_body,
                allow_redirects=False,
                stream=True,
                timeout=30  # Default timeout
            )
            
            # Execute post-request hook
            modified_response = self.hook_manager.execute_hook('post_request', response, trace_id, target_url)
            if modified_response and isinstance(modified_response, requests.Response):
                response = modified_response
            
            # Get response headers
            response_headers = {k: v for k, v in response.headers.items()}
            response_headers['X-Gateway-Trace-ID'] = trace_id
            
            # Execute pre-response hook
            modified_headers = self.hook_manager.execute_hook('pre_response', response_headers, trace_id, target_url)
            if modified_headers and isinstance(modified_headers, dict):
                response_headers = modified_headers
            
            # Send response
            self._set_response(response.status_code, response_headers)
            
            # Stream response body
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    self.wfile.write(chunk)
            
            # Calculate response time
            response_time_ms = (time.time() - request_start_time) * 1000
            
            # Execute post-response hook
            self.hook_manager.execute_hook('post_response', None, trace_id, target_url, response.status_code)
            
            # Log response
            logger.info(f"[{trace_id}] Received response from {target_url} with status {response.status_code} in {response_time_ms:.2f}ms")
            
        except Exception as e:
            logger.error(f"[{trace_id}] Error proxying request to {target_url}: {e}")
            self._set_response(502)
            self.wfile.write(f"Error proxying request: {str(e)}".encode('utf-8'))
    
    def do_GET(self):
        """Handle GET requests."""
        self._proxy_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        self._proxy_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests."""
        self._proxy_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        self._proxy_request('DELETE')
    
    def do_PATCH(self):
        """Handle PATCH requests."""
        self._proxy_request('PATCH')
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        self._proxy_request('HEAD')
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests."""
        self._proxy_request('OPTIONS')


class HTTPServerV6(HTTPServer):
    """HTTP server with IPv6 support."""
    
    address_family = socket.AF_INET6


class GatewayRouter:
    """Main gateway router application."""
    
    def __init__(self, config_file: str = 'config.ini'):
        """Initialize the gateway router with configuration."""
        self.config = Configuration(config_file)
        self.db_manager = None
        self.route_manager = None
        self.hook_manager = None
        self.server = None
    
    def initialize(self):
        """Initialize all components."""
        # Initialize database manager
        db_config = self.config.get_db_config()
        self.db_manager = DatabaseManager(db_config)
        self.db_manager.initialize()
        
        # Initialize route manager
        servers_mapping = self.config.get_servers_mapping()
        self.route_manager = RouteManager(self.db_manager, servers_mapping)
        
        # Initialize hook manager
        hooks_config = self.config.get_hooks_config()
        self.hook_manager = HookManager(hooks_config)
        
        logger.info("Gateway Router initialized successfully")
    
    def start(self):
        """Start the HTTP server."""
        server_config = self.config.get_server_config()
        host = server_config['host']
        port = server_config['port']
        
        # Create request handler class with our managers
        handler = lambda *args, **kwargs: RequestHandler(
            *args,
            route_manager=self.route_manager,
            hook_manager=self.hook_manager,
            **kwargs
        )
        
        # Create and start HTTP server
        try:
            # Try IPv6 first
            self.server = HTTPServerV6((host, port), handler)
            logger.info(f"Starting server on [{host}]:{port} (IPv6)")
        except Exception:
            # Fall back to IPv4
            self.server = HTTPServer((host, port), handler)
            logger.info(f"Starting server on {host}:{port} (IPv4)")
        
        try:
            logger.info("Server started. Press Ctrl+C to stop.")
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopping...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the HTTP server and clean up resources."""
        if self.server:
            self.server.server_close()
            logger.info("Server stopped")
        
        if self.db_manager:
            self.db_manager.close()
        
        logger.info("Gateway Router stopped")


def main():
    """Main entry point for the gateway router application."""
    parser = argparse.ArgumentParser(description='Gateway Router')
    parser.add_argument('--config', '-c', default='config.ini', help='Path to configuration file')
    parser.add_argument('--port', '-p', type=int, help='Server port to use (overrides config file)')
    args = parser.parse_args()
    
    try:
        router = GatewayRouter(args.config)
        router.initialize()
        
        # Override port if specified in command line
        if args.port:
            router.config.config.set('SERVER', 'port', str(args.port))
            logger.info(f"Overriding port with command line argument: {args.port}")
        
        router.start()
    except Exception as e:
        logger.error(f"Failed to start Gateway Router: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()