# Use assetfinder to list subdomains and store them in a variable
subdomains=$(assetfinder pnb.com.my)

# Loop through subdomains and use httpx for each one
echo "$subdomains" | while read -r subdomain; do

    # Run httpx for the subdomain and save the result in a variable
    result=$(httpx -c 300 --follow-redirects "https://$subdomain")
    echo $result
    
    # Run curl and grep on the result to check for CORS issues
    if echo "$result" | curl -m5 -s -I -H "Origin: evil.com" "$subdomain" | grep -q "evil.com"; then
        echo -e "\n\033[0;32m[VUL TO CORS] \033[0m$subdomain"
    fi
done
