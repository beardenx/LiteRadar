# LiteRadar
LiteRadar is a Bash script that provides essential network information and web server analysis for a given target. It offers insights into IP addresses, open ports, TLS/SSL protocols, DNS OSINT, HTTP headers, and web application details.

## Key Features 🚀:

1. Discover IP addresses and pinpoint geolocation.
2. Identify open ports and associated services.
3. WAF detection
4. Detect TLS/SSL protocols and certificate expiry dates.
5. Gather DNS OSINT data, including WHOIS information.
6. Extract crucial HTTP response headers.
7. Perform comprehensive Web Application OSINT.
8. Extract any URLs from the source code

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


