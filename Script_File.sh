#!/bin/bash

#######################################################
# Linux Hardening Script                              #
# Authors: Jaspreet Singh Saini, Tanishq Chotani      #
#######################################################

# This script helps secure your Linux system by implementing several security measures:
# 1. Brute Force Attack Prevention using Fail2Ban
# 2. Privilege Escalation Prevention by managing SUID/SGID files
# 3. Rootkit Detection using RKHunter
# 4. Malware Prevention using ClamAV

# Colors to make output more readable
# These are ANSI color codes that will make text appear in different colors
RED='\033[0;31m'      # Red text for errors
GREEN='\033[0;32m'    # Green text for success
YELLOW='\033[1;33m'   # Yellow text for warnings/info
BLUE='\033[0;34m'     # Blue text for section headers
NC='\033[0m'          # No Color - returns text to default color

# ------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------

# This function checks if the script is run with root (administrator) privileges
# The script needs root privileges to install packages and modify system files
check_root() {
    # $EUID is a special variable that contains the user's ID number
    # Root user always has ID 0
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}This script must be run as root.${NC}"
        echo "Please run with sudo or as the root user."
        exit 1
    else
        echo -e "${GREEN}Root privileges confirmed. Proceeding...${NC}"
    fi
}

# This function displays section headers to organize the output
section_header() {
    echo -e "\n${BLUE}===========================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================${NC}"
}

# Functions to display different types of messages
success_msg() {
    echo -e "${GREEN}[+] $1${NC}"
}

error_msg() {
    echo -e "${RED}[-] $1${NC}"
}

info_msg() {
    echo -e "${YELLOW}[*] $1${NC}"
}

# This function checks if a package is already installed
# It prevents the script from trying to install packages that are already present
is_package_installed() {
    # The command -v checks if a command exists
    # dpkg -l checks if a package is installed
    if command -v $1 >/dev/null 2>&1 || dpkg -l | grep -q $1; then
        return 0    # Return "true" (package is installed)
    else
        return 1    # Return "false" (package is not installed)
    fi
}

# This function installs packages
install_package() {
    local package=$1
    info_msg "Installing $package..."
    
    # Update package list and install the package
    apt-get update && apt-get install -y $package
    
    # Check if installation was successful
    if [ $? -eq 0 ]; then
        success_msg "$package installed successfully"
    else
        error_msg "Failed to install $package"
        return 1
    fi
    return 0
}

# This function creates backups of configuration files before modifying them
# This is good practice so you can restore the original configuration if needed
backup_config() {
    local config_file=$1
    local backup_dir="/root/hardening_backups"
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$backup_dir" ]; then
        mkdir -p "$backup_dir"
    fi
    
    # Copy the file with a timestamp in the name
    if [ -f "$config_file" ]; then
        cp "$config_file" "$backup_dir/$(basename $config_file).$(date +%Y%m%d-%H%M%S).bak"
        success_msg "Backed up $config_file"
    else
        error_msg "Config file $config_file does not exist"
    fi
}

# ------------------------------------------------------------
# BRUTE FORCE ATTACK PREVENTION USING FAIL2BAN
# ------------------------------------------------------------

# This function installs and configures Fail2Ban to prevent brute force attacks
# Fail2Ban monitors log files and bans IP addresses that show malicious signs
setup_fail2ban() {
    section_header "Setting up Fail2Ban (Brute Force Prevention)"
    
    # Check if Fail2Ban is already installed
    if ! is_package_installed fail2ban; then
        install_package fail2ban
    else
        success_msg "Fail2Ban is already installed"
    fi
    
    # Backup the configuration file before modifying it
    backup_config "/etc/fail2ban/jail.conf"
    backup_config "/etc/fail2ban/fail2ban.conf"
    
    info_msg "Configuring Fail2Ban..."
    
    # Create a custom configuration file (jail.local)
    # This configuration sets up Fail2Ban to monitor SSH and ban IPs after 3 failed attempts
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban hosts for one hour:
bantime = 3600

# Use iptables to ban IPs:
banaction = iptables-multiport

# Enable logging to syslog
logtarget = SYSLOG

findtime = 600

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    # Restart the Fail2Ban service to apply the new configuration
    systemctl restart fail2ban
    
    success_msg "Fail2Ban has been configured to prevent brute force attacks"
    info_msg "SSH is now protected with a 3-strike policy before IP ban"
}

# ------------------------------------------------------------
# PRIVILEGE ESCALATION PREVENTION (SUID/SGID)
# ------------------------------------------------------------

# This function handles SUID/SGID files to prevent privilege escalation
# SUID/SGID are special permissions that can be exploited by attackers
handle_suid_sgid() {
    section_header "Handling SUID/SGID Files (Privilege Escalation Prevention)"
    
    info_msg "Creating a list of all SUID/SGID files for reference..."
    
    # Find all files with SUID or SGID permissions
    # -perm -4000 finds SUID files, -perm -2000 finds SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > /root/suid_sgid_files.txt
    
    success_msg "List of SUID/SGID files saved to /root/suid_sgid_files.txt"
    
    # Create a list of known safe SUID/SGID binaries
    # These are standard system tools that legitimately need these permissions
    cat > /root/safe_suid_sgid.txt <<EOF
/bin/mount
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/sudoedit
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/sbin/pppd
EOF
    
    info_msg "Identifying potentially dangerous SUID/SGID files..."
    
    # Compare the lists to find potentially dangerous SUID/SGID files
    # This uses grep to filter out the known safe files
    grep -v -f /root/safe_suid_sgid.txt /root/suid_sgid_files.txt > /root/dangerous_suid_sgid.txt
    
    # Check if any potentially dangerous files were found
    if [ -s /root/dangerous_suid_sgid.txt ]; then
        info_msg "Found potentially dangerous SUID/SGID files:"
        cat /root/dangerous_suid_sgid.txt
        
        # Ask for confirmation before modifying permissions
        read -p "Do you want to disable the SUID/SGID bit on these files? (y/n): " answer
        if [ "$answer" = "y" ]; then
            # Process each file
            while read -r line; do
                # Extract the filename from the ls output
                file=$(echo $line | awk '{print $NF}')
                # Store the original permissions
                original_perm=$(stat -c "%a" $file)
                
                # Backup the file permission
                echo "$file:$original_perm" >> /root/suid_sgid_backup.txt
                
                # Remove SUID/SGID bit using chmod -s
                chmod -s $file
                success_msg "Removed SUID/SGID bit from $file"
            done < /root/dangerous_suid_sgid.txt
        else
            info_msg "Skipping SUID/SGID bit removal"
        fi
    else
        success_msg "No dangerous SUID/SGID files found outside the safe list"
    fi
    
    info_msg "Setting up regular SUID/SGID file monitoring..."
    
    # Create a daily cron job to check for new SUID/SGID files
    # This helps detect if an attacker tries to create new SUID/SGID files
    cat > /etc/cron.daily/check-suid-sgid <<EOF
#!/bin/bash
# Find all SUID/SGID files
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > /root/suid_sgid_files_new.txt

# Compare with previous list to find new files
diff /root/suid_sgid_files.txt /root/suid_sgid_files_new.txt > /root/suid_sgid_diff.txt

# If new files are found, send an alert email
if [ -s /root/suid_sgid_diff.txt ]; then
    echo "New SUID/SGID files detected:" | mail -s "SUID/SGID Alert" root
    cat /root/suid_sgid_diff.txt | mail -s "SUID/SGID Alert Details" root
    cp /root/suid_sgid_files_new.txt /root/suid_sgid_files.txt
fi
EOF
    
    # Make the cron job script executable
    chmod +x /etc/cron.daily/check-suid-sgid
    success_msg "Daily SUID/SGID file monitoring has been set up"
}

# ------------------------------------------------------------
# ROOTKIT DETECTION USING RKHUNTER
# ------------------------------------------------------------

# This function installs and configures RKHunter for rootkit detection
# Rootkits are malicious software that can hide themselves and other malware
setup_rkhunter() {
    section_header "Setting up RKHunter (Rootkit Detection)"
    
    # Check if RKHunter is already installed
    if ! is_package_installed rkhunter; then
        install_package rkhunter
    else
        success_msg "RKHunter is already installed"
    fi
    
    info_msg "Updating RKHunter database..."
    
    # Update RKHunter's database of rootkit signatures
    rkhunter --update
    
    # Create a baseline for the system
    rkhunter --propupd
    
    # Backup the configuration file before modifying
    backup_config "/etc/rkhunter.conf"
    
    info_msg "Configuring RKHunter..."
    
    # Configure email notifications for warnings
    # This replaces any existing MAIL-ON-WARNING line with the new setting
    sed -i 's/^#\?MAIL-ON-WARNING=.*/MAIL-ON-WARNING=root@localhost/' /etc/rkhunter.conf
    
    # Set up daily cron job for RKHunter
    cat > /etc/cron.daily/rkhunter-check <<EOF
#!/bin/bash
# Run RKHunter as a cron job and only report warnings
/usr/bin/rkhunter --cronjob --report-warnings-only
EOF
    
    # Make the cron job script executable
    chmod +x /etc/cron.daily/rkhunter-check
    
    success_msg "RKHunter has been configured for daily rootkit detection"
    info_msg "Running initial RKHunter check..."
    
    # Run initial check with the --sk option (skip keypress)
    rkhunter --check --sk
    
    success_msg "Initial RKHunter check completed"
}

# ------------------------------------------------------------
# ROOTKIT DETECTION USING CHKROOTKIT (ADDITIONAL)
# ------------------------------------------------------------

# This function installs and configures Chkrootkit as a second rootkit detector
# Having two different detection tools provides better coverage
setup_chkrootkit() {
    section_header "Setting up Chkrootkit (Additional Rootkit Detection)"
    
    # Check if Chkrootkit is already installed
    if ! is_package_installed chkrootkit; then
        install_package chkrootkit
    else
        success_msg "Chkrootkit is already installed"
    fi
    
    # Backup the configuration file before modifying
    backup_config "/etc/chkrootkit.conf"
    
    info_msg "Configuring Chkrootkit..."
    
    # Configure to run daily in quiet mode
    echo 'RUN_DAILY="true"' > /etc/chkrootkit.conf
    echo 'RUN_DAILY_OPTS="-q"' >> /etc/chkrootkit.conf
    
    success_msg "Chkrootkit has been configured for daily rootkit detection"
    info_msg "Running initial Chkrootkit scan..."
    
    # Run initial check
    chkrootkit
    
    success_msg "Initial Chkrootkit scan completed"
}

# ------------------------------------------------------------
# MALWARE & TROJAN PREVENTION USING CLAMAV
# ------------------------------------------------------------

# This function installs and configures ClamAV antivirus
# ClamAV is an open source antivirus engine that can detect various malware
setup_clamav() {
    section_header "Setting up ClamAV (Antivirus)"
    
    # Check if ClamAV is already installed
    if ! is_package_installed clamav; then
        install_package clamav
        install_package clamav-daemon
        install_package clamav-freshclam
    else
        success_msg "ClamAV is already installed"
    fi
    
    info_msg "Updating virus definitions..."
    
    # Update the virus definitions database
    systemctl stop clamav-freshclam
    freshclam
    systemctl start clamav-freshclam
    
    info_msg "Setting up daily scan..."
    
    # Create a script for daily scanning
    cat > /etc/cron.daily/clamav-scan <<EOF
#!/bin/bash
# Define log file with timestamp
LOGFILE="/var/log/clamav/scan_$(date +\%Y\%m\%d).log"

# Run a recursive scan of the entire system
# --infected only lists infected files
# exclude-dir prevents scanning virtual filesystems
/usr/bin/clamscan -r --infected --exclude-dir="^/sys|^/proc|^/dev" / > \$LOGFILE 2>&1

# Check if viruses were found (return code 1)
if [ \$? -eq 1 ]; then
    echo "Virus found! Check \$LOGFILE" | mail -s "ClamAV Virus Alert" root
fi
EOF
    
    # Make the cron job script executable
    chmod +x /etc/cron.daily/clamav-scan
    
    # Create log directory if it doesn't exist
    mkdir -p /var/log/clamav
    
    success_msg "ClamAV has been configured for daily malware scanning"
}

# ------------------------------------------------------------
# MAIN EXECUTION FUNCTION
# ------------------------------------------------------------

# This is the main function that calls all the other functions
main() {
    section_header "Linux Hardening Script"
    info_msg "Starting system hardening process..."
    
    # Check if running as root
    check_root
    
    
    # Call each security function
    setup_fail2ban
    handle_suid_sgid
    setup_rkhunter
    setup_chkrootkit
    setup_clamav
    
    section_header "Hardening Complete"
    success_msg "System hardening has been completed successfully"
    info_msg "Log file has been saved to $LOG_FILE"
    
    # Recommend a system reboot
    echo -e "\n${YELLOW}It is recommended to reboot the system to ensure all changes take effect.${NC}"
    read -p "Do you want to reboot now? (y/n): " reboot_answer
    if [ "$reboot_answer" = "y" ]; then
        info_msg "Rebooting the system..."
        reboot
    else
        info_msg "Please remember to reboot the system later."
    fi
}

# Run the main function to start the script
main
