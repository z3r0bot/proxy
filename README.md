# Custom Proxy Server

A simple, lightweight proxy server implementation in Python that can be used for various networking needs.

## Features

- HTTP/HTTPS proxy support
- Multi-threaded client handling
- Non-blocking I/O operations
- Simple configuration
- No external dependencies

## Requirements

- Python 3.6 or higher

## Installation

1. Clone this repository
2. No additional installation required - uses only Python standard library

## Usage

1. Start the proxy server:
```bash
python proxy_server.py
```

2. Configure your application to use the proxy:
   - Host: localhost (or your server's IP)
   - Port: 8080 (default)

## Configuration

You can modify the following parameters in `proxy_server.py`:

- `host`: The IP address to bind to (default: '0.0.0.0')
- `port`: The port to listen on (default: 8080)

## Security Notes

- This is a basic implementation and should be enhanced with additional security measures for production use
- Consider adding:
  - Authentication
  - SSL/TLS support
  - Rate limiting
  - IP filtering
  - Request logging

## Limitations

- Basic HTTP/HTTPS support only
- No built-in authentication
- No SSL/TLS termination
- No caching

## Contributing

Feel free to submit issues and enhancement requests! 