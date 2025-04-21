import socket
import threading
import select
import sys
import time
import logging
import json
import os
import hashlib
import hmac
import base64
from datetime import datetime

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8080, config_file='config.json'):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.clients = []
        self.config_file = config_file
        self.config = self.load_config()
        self.setup_logging()
        self.client_requests = {}  # For rate limiting
        self.rate_limit_window = 60  # 60 seconds window
        self.max_requests = 100  # Max requests per window
        
    def load_config(self):
        """Load configuration from file or use defaults"""
        default_config = {
            "host": "0.0.0.0",
            "port": 8080,
            "auth_enabled": False,
            "username": "admin",
            "password": "password",
            "rate_limit_enabled": True,
            "max_requests_per_minute": 100,
            "allowed_ips": [],
            "blocked_ips": [],
            "log_level": "INFO",
            "log_file": "proxy.log",
            "optimize_for_gaming": True,
            "buffer_size": 16384,  # Increased buffer size
            "timeout": 3,  # Reduced timeout
            "target_servers": ["mc.hypixel.net"],
            "tcp_nodelay": True,
            "tcp_keepalive": True,
            "tcp_keepalive_interval": 30,
            "tcp_keepalive_probes": 3
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                # Create default config file
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                return default_config
        except Exception as e:
            print(f"Error loading config: {e}")
            return default_config
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get("log_level", "INFO"))
        log_file = self.config.get("log_file", "proxy.log")
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("ProxyServer")
    
    def start(self):
        """Start the proxy server"""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set TCP_NODELAY to disable Nagle's algorithm for lower latency
            if self.config.get("tcp_nodelay", True):
                self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
            # Set TCP keepalive
            if self.config.get("tcp_keepalive", True):
                self.server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                # Set keepalive parameters if supported
                try:
                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 
                                          self.config.get("tcp_keepalive_interval", 30))
                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 
                                          self.config.get("tcp_keepalive_interval", 30))
                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 
                                          self.config.get("tcp_keepalive_probes", 3))
                except:
                    pass
                
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            self.running = True
            self.logger.info(f"Proxy server started on {self.host}:{self.port}")
            self.logger.info("Optimized for Hypixel Skyblock with ultra-low latency")
            
            # Start rate limit cleanup thread
            cleanup_thread = threading.Thread(target=self.cleanup_rate_limits)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            while self.running:
                try:
                    client_socket, client_address = self.server.accept()
                    client_ip = client_address[0]
                    
                    # Check if IP is blocked
                    if self.is_ip_blocked(client_ip):
                        self.logger.warning(f"Blocked connection attempt from {client_ip}")
                        client_socket.close()
                        continue
                    
                    # Check if IP is allowed (if allowed_ips is not empty)
                    if not self.is_ip_allowed(client_ip):
                        self.logger.warning(f"Connection from {client_ip} not in allowed list")
                        client_socket.close()
                        continue
                    
                    # Check rate limit
                    if not self.check_rate_limit(client_ip):
                        self.logger.warning(f"Rate limit exceeded for {client_ip}")
                        client_socket.close()
                        continue
                    
                    self.logger.info(f"New connection from {client_address}")
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                    client_thread.daemon = True
                    client_thread.start()
                    self.clients.append(client_socket)
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the proxy server"""
        self.running = False
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        if self.server:
            self.server.close()
        self.logger.info("Proxy server stopped")
    
    def cleanup_rate_limits(self):
        """Periodically clean up old rate limit entries"""
        while self.running:
            time.sleep(self.rate_limit_window)
            current_time = time.time()
            for ip in list(self.client_requests.keys()):
                # Remove requests older than the window
                self.client_requests[ip] = [t for t in self.client_requests[ip] 
                                           if current_time - t < self.rate_limit_window]
                # Remove empty entries
                if not self.client_requests[ip]:
                    del self.client_requests[ip]
    
    def check_rate_limit(self, client_ip):
        """Check if client has exceeded rate limit"""
        if not self.config.get("rate_limit_enabled", True):
            return True
            
        current_time = time.time()
        max_requests = self.config.get("max_requests_per_minute", 100)
        
        if client_ip not in self.client_requests:
            self.client_requests[client_ip] = []
        
        # Remove old requests
        self.client_requests[client_ip] = [t for t in self.client_requests[client_ip] 
                                           if current_time - t < self.rate_limit_window]
        
        # Check if limit exceeded
        if len(self.client_requests[client_ip]) >= max_requests:
            return False
        
        # Add current request
        self.client_requests[client_ip].append(current_time)
        return True
    
    def is_ip_blocked(self, ip):
        """Check if IP is in blocked list"""
        blocked_ips = self.config.get("blocked_ips", [])
        return ip in blocked_ips
    
    def is_ip_allowed(self, ip):
        """Check if IP is in allowed list (if list is not empty)"""
        allowed_ips = self.config.get("allowed_ips", [])
        # If allowed_ips is empty, allow all IPs
        return len(allowed_ips) == 0 or ip in allowed_ips
    
    def authenticate(self, client_socket, client_address):
        """Handle proxy authentication if enabled"""
        if not self.config.get("auth_enabled", False):
            return True
            
        try:
            # Send authentication challenge
            challenge = base64.b64encode(os.urandom(16)).decode('utf-8')
            auth_header = f"Proxy-Authenticate: Basic realm=\"Proxy Authentication Required\"\r\n"
            response = f"HTTP/1.1 407 Proxy Authentication Required\r\n{auth_header}\r\n"
            client_socket.send(response.encode('utf-8'))
            
            # Receive authentication response
            data = client_socket.recv(4096)
            if not data:
                return False
                
            # Parse authentication header
            auth_data = data.decode('utf-8')
            auth_line = None
            for line in auth_data.split('\n'):
                if line.startswith('Proxy-Authorization:'):
                    auth_line = line
                    break
                    
            if not auth_line:
                return False
                
            # Extract credentials
            auth_parts = auth_line.split(' ', 2)
            if len(auth_parts) < 3 or auth_parts[1] != 'Basic':
                return False
                
            credentials = base64.b64decode(auth_parts[2].strip()).decode('utf-8')
            username, password = credentials.split(':', 1)
            
            # Verify credentials
            if (username == self.config.get("username", "admin") and 
                password == self.config.get("password", "password")):
                return True
                
            return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False

    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        client_ip = client_address[0]
        server_socket = None
        try:
            # Set TCP_NODELAY for lower latency
            if self.config.get("tcp_nodelay", True):
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
            # Set TCP keepalive
            if self.config.get("tcp_keepalive", True):
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
            # Check authentication if enabled
            if self.config.get("auth_enabled", False):
                if not self.authenticate(client_socket, client_address):
                    self.logger.warning(f"Authentication failed for {client_ip}")
                    return
            
            # Receive the initial request
            buffer_size = self.config.get("buffer_size", 16384)
            data = client_socket.recv(buffer_size)
            if not data:
                return

            # Try to parse the data as HTTP first
            try:
                # Attempt to decode the request data
                request_data = data.decode('utf-8', errors='ignore')
                
                # Check if this is an HTTP request (starts with a method like GET, POST, CONNECT)
                if request_data.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ', 'CONNECT ')):
                    # This is an HTTP request, handle it as such
                    if request_data.startswith('CONNECT'):
                        # Handle CONNECT request
                        parts = request_data.split(' ', 2)
                        if len(parts) >= 2:
                            host_port = parts[1]
                            if ':' in host_port:
                                host, port = host_port.split(':')
                                port = int(port)
                            else:
                                host = host_port
                                port = 443
                                
                            self.logger.info(f"CONNECT request to {host}:{port} from {client_ip}")
                            
                            # Create connection to target server
                            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            
                            # Set TCP_NODELAY for lower latency
                            if self.config.get("tcp_nodelay", True):
                                server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                                
                            # Set TCP keepalive
                            if self.config.get("tcp_keepalive", True):
                                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                                
                            # Set timeout
                            timeout = self.config.get("timeout", 3)
                            server_socket.settimeout(timeout)
                            
                            # Connect to target server
                            server_socket.connect((host, port))
                            
                            # Send 200 Connection Established
                            client_socket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            
                            # Start forwarding data
                            self.forward_data(client_socket, server_socket, client_ip)
                        else:
                            self.logger.error(f"Invalid CONNECT request format: {request_data}")
                    else:
                        # Handle other HTTP requests
                        lines = request_data.split('\n')
                        if not lines:
                            self.logger.error(f"Empty request from {client_ip}")
                            return
                            
                        first_line = lines[0].strip()
                        parts = first_line.split(' ', 2)
                        
                        if len(parts) < 2:
                            self.logger.error(f"Invalid request format: {first_line}")
                            return
                            
                        method = parts[0]
                        url = parts[1]
                        
                        # Log the request
                        self.logger.info(f"Request: {method} {url} from {client_ip}")
                        
                        # Extract host and port from URL or Host header
                        host = None
                        port = 80
                        
                        # Try to get host from URL
                        if '://' in url:
                            protocol, rest = url.split('://', 1)
                            if '/' in rest:
                                host_port, path = rest.split('/', 1)
                            else:
                                host_port = rest
                                path = ''
                        else:
                            host_port = url
                            path = ''
                            
                        if ':' in host_port:
                            host, port = host_port.split(':')
                            port = int(port)
                        else:
                            host = host_port
                            
                        # If host is still None, try to get it from Host header
                        if host is None:
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    if ':' in host:
                                        host, port = host.split(':')
                                        port = int(port)
                                    break
                                    
                        if host is None:
                            self.logger.error(f"Could not determine host from request: {request_data}")
                            return
                            
                        # Check if this is a Hypixel server connection
                        is_hypixel = any(target in host for target in self.config.get("target_servers", ["mc.hypixel.net"]))
                        if is_hypixel:
                            self.logger.info(f"Hypixel connection detected: {host}:{port}")
                            
                        self.logger.info(f"Connecting to {host}:{port}")
                        
                        # Create connection to target server
                        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        
                        # Set TCP_NODELAY for lower latency
                        if self.config.get("tcp_nodelay", True):
                            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            
                        # Set TCP keepalive
                        if self.config.get("tcp_keepalive", True):
                            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            
                        # Set timeout
                        timeout = self.config.get("timeout", 3)
                        server_socket.settimeout(timeout)
                        
                        # Connect to target server
                        server_socket.connect((host, port))
                        
                        # Forward the request
                        server_socket.send(data)
                        
                        # Start forwarding data
                        self.forward_data(client_socket, server_socket, client_ip)
                else:
                    # This is not an HTTP request, might be Minecraft protocol or other binary protocol
                    # Check if it's a SOCKS request
                    if len(data) > 0 and data[0] == 5:  # SOCKS5
                        self.handle_socks5(client_socket, data, client_ip)
                    else:
                        # Assume it's a direct connection to Hypixel
                        # Default to Hypixel server if not an HTTP request
                        host = self.config.get("target_servers", ["mc.hypixel.net"])[0]
                        port = 25565  # Default Minecraft port
                        
                        self.logger.info(f"Direct connection to Minecraft server: {host}:{port}")
                        
                        # Create connection to target server
                        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        
                        # Set TCP_NODELAY for lower latency
                        if self.config.get("tcp_nodelay", True):
                            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            
                        # Set TCP keepalive
                        if self.config.get("tcp_keepalive", True):
                            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            
                        # Set timeout
                        timeout = self.config.get("timeout", 3)
                        server_socket.settimeout(timeout)
                        
                        # Connect to target server
                        server_socket.connect((host, port))
                        
                        # Forward the initial data
                        server_socket.send(data)
                        
                        # Start forwarding data
                        self.forward_data(client_socket, server_socket, client_ip)
            except Exception as e:
                self.logger.error(f"Error handling request: {e}")
                return
        except Exception as e:
            self.logger.error(f"Error in client handler: {e}")
        finally:
            if client_socket:
                client_socket.close()
            if server_socket:
                server_socket.close()
            if client_socket in self.clients:
                self.clients.remove(client_socket)
    
    def handle_socks5(self, client_socket, initial_data, client_ip):
        """Handle SOCKS5 protocol"""
        try:
            # Send back auth methods response
            client_socket.send(b"\x05\x00")  # No authentication required
            
            # Receive connect request
            data = client_socket.recv(4096)
            if not data or len(data) < 7 or data[0] != 5 or data[1] != 1:  # Must be SOCKS5 CONNECT
                self.logger.error("Invalid SOCKS5 connect request")
                client_socket.close()
                return
                
            # Parse address type
            atyp = data[3]
            if atyp == 1:  # IPv4
                if len(data) < 10:
                    self.logger.error("Invalid IPv4 address in SOCKS5 request")
                    client_socket.close()
                    return
                host = socket.inet_ntoa(data[4:8])
                port = (data[8] << 8) + data[9]
            elif atyp == 3:  # Domain name
                domain_len = data[4]
                if len(data) < 5 + domain_len + 2:
                    self.logger.error("Invalid domain in SOCKS5 request")
                    client_socket.close()
                    return
                host = data[5:5+domain_len].decode('utf-8', errors='ignore')
                port = (data[5+domain_len] << 8) + data[5+domain_len+1]
            else:
                self.logger.error(f"Unsupported address type in SOCKS5: {atyp}")
                client_socket.close()
                return
                
            self.logger.info(f"SOCKS5 request to {host}:{port} from {client_ip}")
            
            # Create connection to target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set TCP_NODELAY for lower latency
            if self.config.get("tcp_nodelay", True):
                server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
            # Set TCP keepalive
            if self.config.get("tcp_keepalive", True):
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
            # Set timeout
            timeout = self.config.get("timeout", 3)
            server_socket.settimeout(timeout)
            
            try:
                # Connect to target server
                server_socket.connect((host, port))
                
                # Send success response
                # Use the same address format as the request
                if atyp == 1:  # IPv4
                    client_socket.send(b"\x05\x00\x00\x01" + socket.inet_aton(host) + 
                                      data[8:10])
                elif atyp == 3:  # Domain name
                    client_socket.send(b"\x05\x00\x00\x03" + bytes([domain_len]) + 
                                      host.encode('utf-8') + data[5+domain_len:5+domain_len+2])
                
                # Start forwarding data
                self.forward_data(client_socket, server_socket, client_ip)
            except Exception as e:
                self.logger.error(f"Error connecting to target in SOCKS5: {e}")
                client_socket.send(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # Host unreachable
                client_socket.close()
                server_socket.close()
                return
                
        except Exception as e:
            self.logger.error(f"Error in SOCKS5 handler: {e}")
            if client_socket:
                client_socket.close()
    
    def forward_data(self, client_socket, server_socket, client_ip):
        """Forward data between client and server sockets"""
        buffer_size = self.config.get("buffer_size", 16384)
        
        # Set sockets to non-blocking mode
        client_socket.setblocking(0)
        server_socket.setblocking(0)
        
        # Set up select for non-blocking I/O
        while True:
            try:
                # Wait for data on either socket
                readable, _, exceptional = select.select([client_socket, server_socket], [], 
                                                        [client_socket, server_socket], 1)
                
                if exceptional:
                    break
                
                for sock in readable:
                    other = server_socket if sock is client_socket else client_socket
                    try:
                        data = sock.recv(buffer_size)
                        if not data:
                            return
                        other.send(data)
                    except socket.timeout:
                        self.logger.warning(f"Socket timeout for {client_ip}")
                        return
                    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError):
                        self.logger.warning(f"Connection error for {client_ip}")
                        return
                    except Exception as e:
                        self.logger.error(f"Error forwarding data: {e}")
                        return
            except Exception as e:
                self.logger.error(f"Error in forward loop: {e}")
                return

if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Ultra-Low Latency Proxy Server for Hypixel Skyblock')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--config', default='config.json', help='Path to config file')
    args = parser.parse_args()
    
    proxy = ProxyServer(host=args.host, port=args.port, config_file=args.config)
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        proxy.stop() 