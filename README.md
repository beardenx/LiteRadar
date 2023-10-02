# LiteRadar
LiteRadar is a Bash script that provides essential network information and web server analysis for a given target. It offers insights into IP addresses, open ports, TLS/SSL protocols, DNS OSINT, HTTP headers, and web application details.

## Key Features 🚀:

1. Quick Subdomain Enumeration
2. Discover IP addresses and pinpoint geolocation.
3. Identify open ports and associated services.
4. WAF detection
5. Detect TLS/SSL protocols and certificate expiry dates.
6. Gather DNS OSINT data, including WHOIS information.
7. Extract crucial HTTP response headers.
8. Perform comprehensive Web Application OSINT.
9. Extract any URLs from the source code

## Dependencies (go)
go is the only dependency
If you do not have "go" installed and configured, please refer to https://go.dev/doc/install

## Getting Started:

To install PortWhisper, follow these steps:
1. Clone the repository:

   ```bash
   git clone https://github.com/beardenx/LiteRadar.git

2. Change Directory & Give Permission:

   ```bash
   cd LiteRadar && chmod +x literadar.sh   

3. Usage :

   ```bash
   Usage: ./literadar.sh [TARGETS]
        : ./literadar.sh google.com 

   Targets must be a domain names without https/http


