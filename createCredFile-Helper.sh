#!/bin/bash
###########################################################################
#
# NAME: CyberArk Privilege Cloud CreateCredFile-Helper Linux Edition
#
# AUTHOR:  Mike Brook <mike.brook@cyberark.com>
#
# COMMENT:
# This tool will help you reset the applicative credentials via API and verify status against Privilege Cloud backend.
#
###########################################################################

#colors
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'
YELLOW='\033[0;33m'


scriptVersion="4"               #update this locally and github.

#Functions

# PVWA Calls
pvwaLogin() {
    rest=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w " %{http_code}" "$pvwaURLAPI/Auth/CyberArk/Logon" \
        --header "Content-Type: application/json" \
        --data @<(
            cat <<EOF
{
	"username": "$adminuser",
	"password": "$adminpass",
	"concurrentSession": "false"
}
EOF
        ))
}

pvwaLogoff() {
    pvwaActivate=$(
        curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Auth/Logoff" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaGetUserId() {
# Call based on UserType (AppProvider, PSMServer etc')
local UserType="$1"
    pvwaGetUser=$(
        curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/Users?filter=componentUser\&search=$credUsername&UserType=$UserType" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaActivateUser() {
    pvwaActivate=$(
        curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Users/$userID/Activate" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaResetPW() {
    pvwaReset=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w "%{http_code}" "$pvwaURLAPI/Users/$userID/ResetPassword" \
        --header "Content-Type: application/json" \
        --header "Authorization: $pvwaHeaders" \
        --data @<(
            cat <<EOF
{
	"id": "$userID",
	"newPassword": "$randomPW",
	"concurrentSession": "false"
}
EOF
        ))
}

pvwaSystemHealthUser() {
    local app_name="$1"
    pvwaSystemHealth=$(
        curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/ComponentsMonitoringDetails/$app_name" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

# Function to check DNS resolution of a URL
check_dns_resolution() {
    local url="$1"
    local hostname
    hostname=$(echo "$url" | awk -F/ '{print $3}')
	# Remove .privilegecloud from the hostname
    hostname=${hostname//.privilegecloud/}
	
	echo "***** Checking we are able to resolve address $hostname"
    if ping -c 1 "$hostname" >/dev/null; then
        echo -e "***** ${GREEN}Hostname ($hostname) resolved successfully.${NC}"
    else
        echo -e "${RED}Can't resolve hostname ($hostname). Please check DNS settings. Aborting...${NC}"
        read -r -p "**** Proceed anyway?: [Y/N]: " response
		if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
			echo "**** Chosen YES"
			sleep 1
		else
			echo "**** Chosen NO, Exiting."
			sleep 1
			exit 1
		fi
    fi
}

creds() {
    read -p "Please Enter Privilege Cloud Install Username: " adminuser
    echo " "
    echo "***** Please Enter Privilege Cloud Install User Password and press ENTER *****"
    read -s adminpass
    if [ -z "$adminpass" ]; then
        echo "password is empty, rerun script"
        exit 1
    else
        adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
    fi
}

restart_services() {
    local serviceName="$1"
    # Check if the operating system is AIX
    if [[ "$(uname -s)" == "AIX" ]]; then
        echo "***** Restarting $serviceName Service on AIX..."
        stopsrc -s ${serviceName}
        startsrc -s ${serviceName}
        lssrc -s ${serviceName}
    else
        echo "***** Restarting $serviceName Service on Linux..."
        systemctl daemon-reload
        systemctl restart "${serviceName}.service"
        systemctl status "${serviceName}.service"
    fi
    sleep 5
}

extract_pvwaURL() {
    local config_file="$1"
    local componentName="$2"
    echo "***** Grabbing PVWA URL from: $configurationFile"
	# if file exists and can be read.
    if [ -r "$configurationFile" ] && [ -s "$configurationFile" ]; then
        # Grab only the first address if ini has multiple.
        if [[ $componentName == aim ]]; then
            pvwaURL=$(cat "$configurationFile" | grep "^ADDRESS" | cut -d'=' -f2 | cut -d',' -f1)
		else # must be psmp.
			pvwaURL=$(cat $configurationFile | grep -oP '(?<=ApplicationRoot=").*?(?=")')
		fi


		# Remove trailing spaces
		pvwaURL=$(echo "$pvwaURL" | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
		# Check if it's not in IP format; we need it for API calls.
		if echo "$pvwaURL" | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/'
		then
			read -r -p "Address is in IP format. Please enter the address in DNS format (example https://mikeb.cyberark.cloud): " pvwaURL
		else
			echo "Retrieved Address: $pvwaURL"
		fi


		
		# handle AIM since we grab vault address from vault.ini
		if [[ $pvwaURL == vault-* ]]; then
			# trim the "vault-" part
			pvwaURL="${pvwaURL#vault-}"
		else
			# If it doesn't start with "vault-", use the address as is
			pvwaURL="$pvwaURL"
		fi
		
		echo -e "***** PVWA URL is: ${GREEN}$pvwaURL${NC}"
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
		else
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
		fi
    else
		read -r -p "Couldn't grab PVWA URL, please enter it manually (e.g., https://mikeb.cyberark.cloud):" pvwaURL
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		# Check if URL belongs to UM env; otherwise, use legacy.
		if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
		else
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
		fi
	fi
}

main() {
    clear
    echo "***** To perform this task, we must be able to reach your cloud portal (e.g., https://mikeb.privilegecloud.cyberark.cloud) via HTTPS/443."
    echo ""
    read -r -p "***** Do you want to continue? [Y/N] " response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "***** Selected YES..."
        # Grab PVWA URL
        extract_pvwaURL "$configurationFile" "$component_name"

        # Check if the hostname is resolvable before proceeding
        check_dns_resolution "$pvwaURLAPI"

        # PVWA Login
        echo "***** Establishing connection to PVWA..."
        echo "***** Calling: $pvwaURLAPI"
        creds     # get user input
        pvwaLogin # call login
        if [[ $(echo "$rest" | grep "200") ]]; then
            echo -e "***** ${GREEN}Connected!${NC}"
            # Grab headers
            pvwaHeaders=$(echo "$rest" | cut -d' ' -f1 | tr -d '"')
        else
            echo -e "***** ${RED}Connection failed...${NC}"
            echo "http response code: $rest"
            echo -e "***** ${RED}Unable to proceed, fix connection to PVWA and rerun the script.${NC}"
            exit 1
        fi

        for n in ${credfiles[@]}; do #both app and gw
            echo "***** Generating CredFile: $n"
            if [ -s $n ]; then #check file not empty
                credUsername=$(cat $n | grep -oP '(?<=Username=).*(?=)')
                echo -e "***** Grabbed username: ${PURPLE}$credUsername${NC}"
                #generate random temp pw from 2 methods and combine them to create a strong pw.
                randomPW1=$(
                    tr -dc A-Za-z0-9 </dev/urandom | head -c 13
                    echo ''
                )
                randomPW2=$(date | md5sum) && randomPWtrim=$(echo $randomPW2 | cut -d' ' -f1)
                randomPW="${randomPW1}${randomPWtrim::-27}" #-27 to avoid the 39 char limit and repeating chars.
                $createcredfile $n Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
                #get user ID
                echo "***** Retrieving UserID for user $credUsername"
                pvwaGetUserId "$compUserType"
                userID=$(echo $pvwaGetUser | grep -oP '(?<="id":).*?(?=,)') # grabs user id
                echo "***** userID: $userID"
                echo "***** Activating/Unsuspending user: $credUsername just in case."
                pvwaActivateUser
                sleep 1
                if [[ $pvwaActivate == 200 ]]; then
                    echo -e "***** ${GREEN}Successfully Activated: $credUsername${NC}"
                else
                    echo -e "***** ${RED}Failed Activating: $credUsername${NC}"
                    echo $pvwaActivate
                    exit 1
                fi
                echo "***** Resetting Password user: $credUsername"
                pvwaResetPW # call reset pw
                sleep 1
                if [[ $(echo $pvwaReset | grep "200") ]]; then
                    echo -e "***** ${GREEN}Successfully Restet Password: $credUsername${NC}"
                else
                    echo -e "***** ${RED}Failed Resetting Password: $credUsername${NC}"
                    echo $pvwaReset
                    exit 1
                fi
            else
                echo "***** File is empty or corrupted, aborting..."
                exit 1
            fi
        done

        restart_services "$service"
        echo "***** Checking to see if service is back online via SystemHealth."
        pvwaSystemHealthUser "$appName"
        # grab only relevant username and cut everything except IsLoggedOn "true" or "false"
        appName=$(echo $credUsername | cut -d'_' -f2) #better to search the exact name instead of with app/gw prefix.
        status=$(echo $pvwaSystemHealth | grep -oP "($appName).*?(?="LastLogonDate")" | grep -oP '(?<="IsLoggedOn":).*?(?=,)')
        if [[ $(echo $status | grep "true") ]]; then
            echo -e "***** ${GREEN}$appName Is : Online!${NC}"
        else
            echo -e "***** ${RED}$appName Is : Offline!${NC}"
            echo -e "***** ${RED}Return call was: $status${NC}"
            echo -e "***** Something went wrong :( you'll have to reset it manually with CyberArk's help."
            pvwaLogoff
            exit 1
        fi
        # Logoff
        pvwaLogoff
        exit 1

    else
        echo "***** Selected NO..."
        echo "***** Exiting..."
        exit 1
    fi
}

if [ "$EUID" -ne 0 ]; then
    read -p "***** Please run as root - Press ENTER to exit..."
    exit 1
fi

# check we are not running from /tmp/ folder, its notorious for permission issues.
if [[ $PWD = /tmp ]] || [[ $PWD = /tmp/* ]]; then
    read -p "***** Detected /tmp folder, it is known for problematic permission issues, please move to another folder and try again...."
    exit 1
fi

clear
echo "--------------------------------------------------------------"
echo "----------- CyberArk CreateCredFile-Helper for NIX -----------"
echo "----------- Script version "$scriptVersion" ---------------------------------"
echo "--------------------------------------------------------------"

declare -a components_found=()

# Check if CARKpsmp component exists
if [ -f "/opt/CARKpsmp/bin/createcredfile" ]; then
    components_found+=("psmp")
fi

# Check if CARKaim component exists
if [ -f "/opt/CARKaim/bin/createcredfile" ]; then
    components_found+=("aim")
fi

# If no components are found, exit
if [ ${#components_found[@]} -eq 0 ]; then
    echo "No CyberArk services detected."
    exit 1
fi

# List the components found and prompt for user selection
echo "CyberArk services detected on this machine:"
for i in "${!components_found[@]}"; do
    echo -e "${GREEN}$((i+1)). ${components_found[i]}${NC}"
done

read -p "Please choose a service to reset cred files (1-${#components_found[@]}): " choice
component_name="${components_found[$((choice-1))]}"

# Set the variables based on the user's choice
case $component_name in
    "psmp")
        echo "CARKpsmp component selected."
        credfiles=("/etc/opt/CARKpsmp/vault/psmpappuser.cred" "/etc/opt/CARKpsmp/vault/psmpgwuser.cred")
        createcredfile="/opt/CARKpsmp/bin/createcredfile"
        configurationFile="/var/opt/CARKpsmp/temp/PVConfiguration.xml"
        service="psmpsrv"
        appName="SessionManagement"
		compUserType="PSMPServer"
        ;;
    "aim")
        echo "CARKaim component selected."
        credfiles=("/etc/opt/CARKaim/vault/appprovideruser.cred")
        createcredfile="/opt/CARKaim/bin/createcredfile"
        configurationFile="/etc/opt/CARKaim/vault/vault.ini"
        service="aimprv"
        appName="AIM"
		compUserType="AppProvider"
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac


main
