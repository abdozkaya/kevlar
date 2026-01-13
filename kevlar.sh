#!/bin/bash

# ==============================================================================
# PROJECT: KEVLAR - Production Ready VPS Hardening
# VERSION: 1.0.0
# AUTHOR:  abdozkaya
# LICENSE: MIT
# TARGET:  Ubuntu 20.04+, Debian 11+
# ==============================================================================

# --- CONFIGURATION ---
APP_NAME="KEVLAR"
BACKUP_DIR="/root/kevlar_backups_$(date +%F_%T)"
LOG_FILE="/var/log/kevlar_install.log"

# --- COLORS (Fixed) ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- HELPER FUNCTIONS ---
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERR]${NC}  $1" | tee -a "$LOG_FILE"; }

backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak"
    fi
}

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
   log_error "Critical: This script requires root privileges."
   exit 1
fi

# --- BANNER & INTRO ---
clear
echo -e "${CYAN}"
cat << "EOF"
 __  ___  ___________    ____  __          ___      .______      
|  |/  / |   ____\   \  /   / |  |        /   \     |   _  \     
|  '  /  |  |__   \   \/   /  |  |       /  ^  \    |  |_)  |    
|    <   |   __|   \      /   |  |      /  /_\  \   |      /     
|  .  \  |  |____   \    /    |  `----./  _____  \  |  |\  \----.
|__|\__\ |_______|   \__/     |_______/__/     \__\ | _| `._____|
                                              
EOF
echo -e "${NC}"
echo -e "${YELLOW}>>> WELCOME TO KEVLAR.${NC}"
echo -e "Your server is currently naked in a warzone."
echo -e "Let's suit it up with military-grade armor. Right now."
echo -e "---------------------------------------------------------"

# --- INITIAL SETUP ---
echo ""
log_info "Initializing Setup Wizard..."

# 1. User
read -p "1. New Sudo Username [admin]: " SYS_USER
SYS_USER=${SYS_USER:-admin}

while true; do
    read -s -p "2. Password for $SYS_USER: " SYS_PASS
    echo ""
    read -s -p "   Confirm Password: " SYS_PASS_CONFIRM
    echo ""
    [ "$SYS_PASS" = "$SYS_PASS_CONFIRM" ] && break
    log_error "Passwords do not match. Try again."
done

# 2. Port
read -p "3. New SSH Port [2222]: " SSH_PORT
SSH_PORT=${SSH_PORT:-2222}

# 3. SSH Key
echo ""
echo -e "${YELLOW}4. Paste Public SSH Key (ssh-rsa ...)${NC}"
echo -e "   ${CYAN}(Leave empty to keep Password Auth enabled)${NC}"
read -p "   Key: " USER_SSH_KEY

# --- MODE SELECTION ---
echo ""
echo -e "${YELLOW}Select Execution Mode:${NC}"
echo -e "   [1] ${GREEN}AUTO${NC}   (Install everything, ask nothing)"
echo -e "   [2] ${CYAN}MANUAL${NC} (Decide step-by-step with Help support)"
read -p "Choice [1]: " MODE
MODE=${MODE:-1}

# --- EXECUTION ENGINE (Smart Logic) ---
run_task() {
    local func=$1
    local title=$2
    local help_text=$3
    
    if [[ "$MODE" == "2" ]]; then
        while true; do
            echo ""
            echo -e "${CYAN}>>> TASK: ${NC}$title"
            read -p "    Execute? (y/n/h): " choice
            case "$choice" in
                y|Y) 
                    $func 
                    break 
                    ;;
                n|N) 
                    log_warn "Skipped: $title" 
                    break 
                    ;;
                h|H) 
                    echo -e "${YELLOW}??? WHY IS THIS NEEDED? ???${NC}"
                    echo -e "$help_text"
                    echo -e "---------------------------"
                    ;;
                *) 
                    echo "Invalid key. Use 'y', 'n' or 'h'." 
                    ;;
            esac
        done
    else
        # Auto Mode
        echo ""
        log_info "Running: $title"
        $func
    fi
}

# --- TASKS ---

task_update() {
    log_info "Updating package lists..."
    apt-get update -qq 
    log_info "Upgrading existing packages..."
    apt-get upgrade -y -qq
    # Install only base essentials required for the script to run
    apt-get install -y -qq curl vim sudo net-tools
    log_success "System updated & Base tools installed."
}

task_time() {
    apt-get install -y -qq systemd-timesyncd
    timedatectl set-ntp on
    timedatectl set-timezone UTC
    log_success "Timezone set to UTC & NTP synced."
}

task_swap() {
    local ram=$(free -m | awk '/^Mem:/{print $2}')
    if [[ "$ram" -lt 2048 ]] && [[ -z $(swapon --show) ]]; then
        log_info "RAM is low ($ram MB). Creating Swap..."
        fallocate -l 1G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        log_success "1GB Swap created."
    else
        log_success "Swap not needed or already exists."
    fi
}

task_cleanup() {
    apt-get purge -y telnet rsh-client rsh-server talk yp-tools xinetd tftp-hpa vsftpd wu-ftpd > /dev/null 2>&1
    apt-get autoremove -y > /dev/null 2>&1
    log_success "Insecure packages (Telnet/FTP etc.) purged."
}

task_user() {
    if ! id "$SYS_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$SYS_USER"
        echo "$SYS_USER:$SYS_PASS" | chpasswd
        usermod -aG sudo "$SYS_USER"
        log_success "User $SYS_USER created."
    else
        log_warn "User $SYS_USER already exists."
    fi
    chmod 750 /home/$SYS_USER
    passwd -l root > /dev/null 2>&1
    
    if [[ -n "$USER_SSH_KEY" ]]; then
        mkdir -p /home/$SYS_USER/.ssh
        echo "$USER_SSH_KEY" >> /home/$SYS_USER/.ssh/authorized_keys
        chmod 700 /home/$SYS_USER/.ssh
        chmod 600 /home/$SYS_USER/.ssh/authorized_keys
        chown -R $SYS_USER:$SYS_USER /home/$SYS_USER/.ssh
        log_success "SSH Key imported."
    fi
}

task_ssh() {
    local cfg="/etc/ssh/sshd_config"
    backup_file "$cfg"
    
    # Configs
    sed -i "s/#Port 22/Port $SSH_PORT/" $cfg
    sed -i "s/Port 22/Port $SSH_PORT/" $cfg
    if ! grep -q "^Protocol 2" $cfg; then echo "Protocol 2" >> $cfg; fi
    
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' $cfg
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' $cfg
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' $cfg
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' $cfg
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' $cfg
    sed -i 's/#Banner none/Banner \/etc\/issue.net/' $cfg
    
    if [[ -n "$USER_SSH_KEY" ]]; then
        sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' $cfg
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' $cfg
    fi

    echo "WARNING: Authorized access only. All activity is logged." > /etc/issue.net
    log_success "SSH Hardened (Port: $SSH_PORT)."
}

task_firewall() {
    log_info "Installing UFW..."
    apt-get install -y -qq ufw
    
    ufw --force reset > /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SSH_PORT"/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    echo "y" | ufw enable
    log_success "Firewall (UFW) installed & enabled."
}

task_fail2ban() {
    log_info "Installing Fail2Ban..."
    apt-get install -y -qq fail2ban
    
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sed -i "s/port = ssh/port = $SSH_PORT/" /etc/fail2ban/jail.local
    cat <<EOF >> /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
    systemctl restart fail2ban
    systemctl enable fail2ban
    log_success "Fail2Ban installed & protection active."
}

task_audit() {
    log_info "Installing Auditd & Rkhunter..."
    apt-get install -y -qq auditd audispd-plugins rkhunter
    rkhunter --propupd > /dev/null 2>&1
    log_success "Audit tools installed."
}

task_network() {
    backup_file "/etc/sysctl.conf"
    cat <<EOF > /etc/sysctl.d/99-kevlar.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.ip_forward = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
EOF
    sysctl -p /etc/sysctl.d/99-kevlar.conf > /dev/null
    log_success "Kernel Network Stack hardened."
}

task_autoupdate() {
    log_info "Installing Unattended Upgrades..."
    apt-get install -y -qq unattended-upgrades apt-listchanges
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
    log_success "Auto-security updates enabled."
}

task_shm() {
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
        mount -o remount /dev/shm
        log_success "Shared Memory (/dev/shm) secured."
    fi
}

# --- RUNNER LOOP ---

run_task task_update \
    "System Update & Base Tools" \
    "Updates all packages to latest versions and installs basic tools (curl, vim). ESSENTIAL."

run_task task_time \
    "NTP Time Sync" \
    "Syncs server time with global standards (UTC). Crucial for correct logs and 2FA."

run_task task_swap \
    "Smart Swap Creation" \
    "Checks RAM. If <2GB, creates a 1GB Swap file. Prevents crashes during updates."

run_task task_cleanup \
    "Remove Bloatware" \
    "Removes insecure legacy protocols (Telnet, FTP, etc.) that hackers love to exploit."

run_task task_user \
    "User Setup & Lock Root" \
    "Creates your new admin user and LOCKS the Root account to prevent direct attacks."

run_task task_ssh \
    "SSH Hardening" \
    "Changes SSH Port ($SSH_PORT), blocks Root login, and restricts auth attempts."

run_task task_firewall \
    "Firewall Setup (UFW)" \
    "Installs UFW. Blocks ALL incoming traffic except SSH, HTTP, and HTTPS."

run_task task_fail2ban \
    "Fail2Ban Protection" \
    "Installs Fail2Ban. Automatically bans IPs that try to guess your password."

run_task task_audit \
    "Audit & Rootkit Hunter" \
    "Installs tools to monitor system changes and scan for hidden viruses/rootkits."

run_task task_network \
    "Network Stack Hardening" \
    "Modifies Kernel settings to block IP Spoofing, SYN Floods, and other network attacks."

run_task task_autoupdate \
    "Auto-Security Updates" \
    "Automatically installs critical security patches without your intervention."

run_task task_shm \
    "Secure Shared Memory" \
    "Prevents hackers from running malicious scripts in the RAM (/dev/shm)."


# --- COMPLETION ---
systemctl restart ssh

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "   MISSION ACCOMPLISHED. SYSTEM SECURED."
echo -e "${GREEN}==========================================${NC}"
echo -e " User: ${YELLOW}$SYS_USER${NC}"
echo -e " Port: ${YELLOW}$SSH_PORT${NC}"
if [[ -n "$USER_SSH_KEY" ]]; then
    echo -e " Auth: ${GREEN}SSH KEY ONLY${NC}"
else
    echo -e " Auth: ${RED}PASSWORD${NC} (Warning: Add a key soon!)"
fi
echo -e "------------------------------------------"
echo -e "${RED}IMPORTANT:${NC} Do NOT close this session yet."
echo -e "Test connection in a NEW terminal:"
echo -e "${CYAN}ssh -p $SSH_PORT $SYS_USER@$(curl -s ifconfig.me)${NC}"
echo -e "=========================================="
