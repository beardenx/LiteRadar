#!/bin/bash

# print underlined text
underline() {
  echo -e "\e[33m\e[4m$1\e[0m"
}

# Function to determine the protocol (http or https) to use for whatweb
determine_protocol() {
    local domain="$1"
    local protocol="http"

    # Check if the domain supports HTTPS by attempting to fetch its SSL certificate
    if curl --head --insecure --silent "https://$domain" | grep "200 OK" >/dev/null; then
        protocol="https"
    fi

    echo "$protocol"
}

validate_domain() {
    local domain_pattern="^([a-zA-Z0-9.-]+)$"
    if [[ "$1" =~ $domain_pattern ]]; then
        echo "${BASH_REMATCH[0]}"
        return 0  # Valid domain
    else
        return 1  # Invalid input
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check and install dependencies
install_dependencies() {
    local dependencies=("wafw00f" "nmap" "openssl" "whatweb")

    echo "[+] Checking Dependencies ..."

    for dep in "${dependencies[@]}"; do
        if ! command_exists "$dep"; then
            case "$dep" in
                "wafw00f")
                    pip install wafw00f >/dev/null 2>&1
                    ;;
                *)
                    sudo apt-get install -y "$dep" >/dev/null 2>&1
                    ;;
            esac

            # Check if the installation was successful
            if [ $? -eq 0 ]; then
                echo "[+] Installed Dependency: $dep"
            fi
        fi
    done

    if ! command_exists "go"; then
        echo "[-] 'go' is not installed. Please refer https://go.dev/dl/ to install go"
    else
        echo "[+] 'go' is installed."
        echo "[+] Installing assetfinder..."

        # Clone the assetfinder repository
        git clone https://github.com/tomnomnom/assetfinder.git
        cd assetfinder

        # Initialize a Go module
        go mod init assetfinder

        # Build assetfinder
        go build .

        # Move assetfinder to /usr/local/bin/
        sudo mv assetfinder /usr/local/bin/

        # Check if assetfinder is installed
        if command_exists "assetfinder"; then
            echo "[+] assetfinder is now installed."
        else
            echo "[-] Failed to install assetfinder. Please install it manually."
        fi

        cd ..
    fi

    echo "[+] Checking Dependencies completed. All tools are installed if needed."
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check WAF with wafw00f and display custom WAF info
check_WAF_with_wafw00f() {
    local waf_info="Undetected"
    local wafw00f_output
    wafw00f_output=$(wafw00f -v "$1" 2>&1)

    if [[ "$wafw00f_output" == *"is behind"* ]]; then
        waf_info=$(grep -oP "is behind \K[^(]*" <<< "$wafw00f_output" | sed 's/\x1B\[[0-9;]*m//g')
        echo "[+] Web Application Firewall detected: $waf_info"
    else
        echo "[+] Web Application Firewall: Undetected"
    fi
}

# Function to check open ports and running services using nmap
check_port_services_with_nmap() {
    local target="$1"
    local nmap_result
    nmap_result=$(nmap -T4 -F "$target")
    open_ports=$(echo "$nmap_result" | grep '^[0-9]' | awk '{print $1}' | tr '\n' ', ')
    services=$(echo "$nmap_result" | grep '^[0-9]' | awk '{print $3}' | tr '\n' ', ')

    echo "[+] Open Ports:  $open_ports"
    echo "[+] Services:  $services"
}

# Function to check TLS protocol versions using nmap
check_tls_versions_with_nmap() {
    local target="$1"
    local tls_versions=("TLSv1.3" "TLSv1.2" "TLSv1.1" "TLSv1.0" "SSLv2" "SSLv3")

    # Run nmap once to get all the TLS versions in one go
    local nmap_result
    nmap_result=$(nmap -Pn --script ssl-enum-ciphers -p 443 "$target" 2>&1)

    # Check each TLS version in the result and display one by one
    for version in "${tls_versions[@]}"; do
        if echo "$nmap_result" | grep -q "$version"; then
            echo "[+] $version: Enabled"
        else
            echo "[+] $version: Disabled"
        fi
    done
}

# Function to check TLS expiry using openssl
check_tls_expiry_with_openssl() {
    local ssl_cert_info
    ssl_cert_info=$(openssl s_client -showcerts -servername "$1" -connect "$1:443" </dev/null 2>/dev/null | grep -oP 'NotAfter: \K[^;]*' | head -n 1)

    if [ -n "$ssl_cert_info" ]; then
        echo "[+] Expiry Dates: $ssl_cert_info"
    else
        echo -e "[+] Expiry Dates: \e[31mNo Expiry Date. SSL Certificates may not be supported.\e[0m"
    fi
}


# Function to retrieve the target's IP addresses
get_ip_addresses() {
    local domain="$1"
    local ip_addresses
    ip_addresses=$(host "$domain" 2>&1 | awk '/has address/ {print $4}')
    
    if [[ -n "$ip_addresses" ]]; then
        # Join the IP addresses with commas
        ip_addresses=$(echo "$ip_addresses" | tr '\n' '/ ')
        echo "[+] IP Addresses: $ip_addresses"
    else
        echo "[+] Failed to retrieve IP addresses."
    fi
}

# Function to retrieve geolocation information for the target IP
get_geolocation() {
    local ip_addresses
    ip_addresses=$(host "$1" 2>&1 | awk '/has address/ {print $4}')
    
    if [[ -n "$ip_addresses" ]]; then
        echo "[+] Geolocation Information:"
        local geolocation_info

        for ip_address in $ip_addresses; do
            geolocation_info=$(curl -s "https://ipinfo.io/$ip_address/json?$(date +%s)" 2>&1)
            if [[ $? -eq 0 ]]; then
                echo "$geolocation_info"
            else
                echo "[+] Failed to retrieve geolocation information for IP address: $ip_address"
            fi
        done
    else
        echo "[+] Failed to retrieve IP addresses or geolocation information."
    fi
}


# Function to retrieve specific HTTP response headers using nmap
get_specific_http_headers_with_nmap() {
    local target="$1"
    local http_response
    http_response=$(nmap -Pn -p 443 --script http-headers "$target" 2>&1)
    
    local headers
    headers=$(echo "$http_response" | grep -oP '(Strict-Transport-Security|X-XSS-Protection|X-Content-Type-Options|X-Frame-Options|Content-Security-Policy): .*')
    
    if [[ -n "$headers" ]]; then
        echo "[+] HTTP Response Headers:"
        echo "$headers"
    else
        echo "[+] HTTP Headers may not be configured"
    fi
}

# Function to perform WHOIS lookup and display specific details
perform_whois() {
    local domain="$1"
    local whois_info
    whois_info=$(whois "$domain" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "[+] WHOIS Information:"
        echo "$whois_info" | grep -Ei "Domain Name:|Updated Date:|Creation Date:|Registry Expiry Date:" | tr '[:upper:]' '[:lower:]' | awk -F ': ' '!seen[$2]++'
    else
        echo "[+] Failed to retrieve WHOIS information."
    fi
}

# Function to extract the base domain from a given domain
extract_base_domain() {
    local domain="$1"

    # Remove any leading "www." and split by dots
    local parts=($(echo "$domain" | sed 's/^www\.//' | tr '.' ' '))

    local num_parts=${#parts[@]}

    if [[ "$num_parts" -ge 2 ]]; then
        local base_domain="${parts[$num_parts-2]}.${parts[$num_parts-1]}"
        echo "$base_domain"
    else
        echo "$domain"
    fi
}

# Function to interactively extract and confirm the base domain from a given domain
extract_and_confirm_base_domain() {
    local domain="$1"

    local base_domain=$(extract_base_domain "$domain")

    read -p $'\e[32m[+] Generating the Base Domain: \e[0m'"$base_domain, is this correct? (Y/N): " user_input

    if [[ "$user_input" == "N" || "$user_input" == "n" ]]; then
        read -p $'\e[32mPlease enter the correct base domain:\e[0m' corrected_base
        base_domain="$corrected_base"
    fi

    echo "[+] Enumerating subdomains for $base_domain"

    # Perform subdomain enumeration using Amass directly here
    local subdomains
    subdomains=$(assetfinder "$base_domain" 2>/dev/null | sort -u)

    if [[ -n "$subdomains" ]]; then
        echo "[+] Subdomains: for $base_domain"
        echo
        echo "$subdomains"
    else
        echo "[+] No subdomains found."
    fi
}

# Function to identify web server technology and banner grabbing
identify_web_server() {
    local domain="$1"
    local server_info
    server_info=$(curl -I -s "$domain" | awk -F ': ' '/^Server:/ {print $2}')
    
    if [[ -n "$server_info" ]]; then
        echo "[+] Server: $server_info"
    else
        echo "[+] Web server information not found."
    fi
}


# Function to extract web application information using 'whatweb' and a loop with awk
extract_web_info() {
    local whatweb_output
    whatweb_output=$(whatweb "$1")

    # Define an array of patterns and corresponding labels
    patterns=("Email" "HTTPServer" "JQuery" "Title" "WordPress" "Joomla" "X-Powered-By")
    labels=("Email" "HTTP Server" "JQuery Version" "Title" "WordPress Version" "Joomla Version" "X-Powered-By")

    # Loop through the patterns and extract the corresponding information using awk
    for ((i = 0; i < ${#patterns[@]}; i++)); do
        info=$(echo "$whatweb_output" | awk -F "${patterns[i]}" 'NF>1{print $2}' | awk -F ']' '{print $1}' | head -n 1)
        if [ -z "$info" ]; then
            info=$'\e[31mNo Info\e[0m'
        fi
        echo "[+] ${labels[i]}: $info"
    done
}

# Function to extract URLs from the source of a webpage
extract_url_in_view_source() {
  local source_url
  source_url=$(curl -s  "$1" | grep -oP '(https*://|www\.)[^ ]*')

  if [[ -n "$source_url" ]]; then
    echo "[+] URLs Found:"
    echo "$source_url" | while read -r line; do
      echo "$line"
    done
  else
    echo "[+] No URLs Found."
  fi
}

# Main function to run the Scout Radar
main() {
    # Check if a target domain is provided as a command line argument
    if [ $# -ne 1 ]; then
        echo "[+] Usage: $0 <domain_target>"
        exit 1
    fi

    # Validate the provided target domain
    domain_target=$(validate_domain "$1")

    if [ -z "$domain_target" ]; then
        echo "[+] Invalid input. Please enter a valid domain without https/http"
        exit 1
    fi

    # Determine the protocol (http or https) to use for whatweb
    protocol=$(determine_protocol "$domain_target")
    whatweb_target="$protocol://$1"

    # Check and install dependencies if needed
    install_dependencies

    # Print network information for the target domain
    echo 
    underline "Network Information for $1"
    get_ip_addresses "$domain_target"
    get_geolocation "$domain_target"
    check_port_services_with_nmap "$domain_target"
    check_WAF_with_wafw00f "$whatweb_target"
    echo

    # Check TLS protocol versions
    underline "TLS/SSL Protocols for $1"
    echo
    check_tls_versions_with_nmap "$domain_target"
    check_tls_expiry_with_openssl "$domain_target"
    echo

     # DNS OSINT Information
    echo 
    underline "DNS OSINT for $1"
    identify_web_server "$whatweb_target"
    perform_whois "$domain_target"
    echo

     # HTTP Response Header
    underline "HTTP Response Headers for $1"
    get_specific_http_headers_with_nmap "$domain_target"
    echo

     # Web App OSINT
    underline "Web Application OSINT for $1"
    extract_web_info "$whatweb_target"
    echo

    underline "URLs Found in Source Code for $1"
    extract_url_in_view_source "$whatweb_target"

    echo 
    underline "Subdomain Enumeration for $1"
    extract_and_confirm_base_domain "$@" 
    echo
}

# Call the main function with command line argument
main "$@"
