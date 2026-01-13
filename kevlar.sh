#!/bin/bash

# ==============================================================================
# PROJECT: KEVLAR - Production Ready VPS Hardening
# VERSION: 1.0.0
# AUTHOR:  abdozkaya
# LICENSE: MIT
# TARGET:  Ubuntu 20.04+, Debian 11+
# ==============================================================================

# --- CONFIGURATION VARIABLES ---
APP_NAME="KEVLAR"
BACKUP_DIR="/root/kevlar_backups_$(date +%F_%T)"
LOG_FILE="/var/log/kevlar_install.log"

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\133[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

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
   log_error "Please run as root (sudo)."
   exit 1
fi

# --- BANNER ---
clear
echo -e "${CYAN}"
cat << "EOF"
                                                                                                                                                  
                                                                                                                                                  
KKKKKKKKK    KKKKKKKEEEEEEEEEEEEEEEEEEEEEEVVVVVVVV           VVVVVVVVLLLLLLLLLLL                            AAA               RRRRRRRRRRRRRRRRR   
K:::::::K    K:::::KE::::::::::::::::::::EV::::::V           V::::::VL:::::::::L                           A:::A              R::::::::::::::::R  
K:::::::K    K:::::KE::::::::::::::::::::EV::::::V           V::::::VL:::::::::L                          A:::::A             R::::::RRRRRR:::::R 
K:::::::K   K::::::KEE::::::EEEEEEEEE::::EV::::::V           V::::::VLL:::::::LL                         A:::::::A            RR:::::R     R:::::R
KK::::::K  K:::::KKK  E:::::E       EEEEEE V:::::V           V:::::V   L:::::L                          A:::::::::A             R::::R     R:::::R
  K:::::K K:::::K     E:::::E               V:::::V         V:::::V    L:::::L                         A:::::A:::::A            R::::R     R:::::R
  K::::::K:::::K      E::::::EEEEEEEEEE      V:::::V       V:::::V     L:::::L                        A:::::A A:::::A           R::::RRRRRR:::::R 
  K:::::::::::K       E:::::::::::::::E       V:::::V     V:::::V      L:::::L                       A:::::A   A:::::A          R:::::::::::::RR  
  K:::::::::::K       E:::::::::::::::E        V:::::V   V:::::V       L:::::L                      A:::::A     A:::::A         R::::RRRRRR:::::R 
  K::::::K:::::K      E::::::EEEEEEEEEE         V:::::V V:::::V        L:::::L                     A:::::AAAAAAAAA:::::A        R::::R     R:::::R
  K:::::K K:::::K     E:::::E                    V:::::V:::::V         L:::::L                    A:::::::::::::::::::::A       R::::R     R:::::R
KK::::::K  K:::::KKK  E:::::E       EEEEEE        V:::::::::V          L:::::L         LLLLLL    A:::::AAAAAAAAAAAAA:::::A      R::::R     R:::::R
K:::::::K   K::::::KEE::::::EEEEEEEE:::::E         V:::::::V         LL:::::::LLLLLLLLL:::::L   A:::::A             A:::::A   RR:::::R     R:::::R
K:::::::K    K:::::KE::::::::::::::::::::E          V:::::V          L::::::::::::::::::::::L  A:::::A               A:::::A  R::::::R     R:::::R
K:::::::K    K:::::KE::::::::::::::::::::E           V:::V           L::::::::::::::::::::::L A:::::A                 A:::::A R::::::R     R:::::R
KKKKKKKKK    KKKKKKKEEEEEEEEEEEEEEEEEEEEEE            VVV            LLLLLLLLLLLLLLLLLLLLLLLLAAAAAAA                   AAAAAAARRRRRRRR     RRRRRRR
                                              
EOF
echo -e "${NC}"
echo -e "   ${APP_NAME} > Production Server Hardening Utility"
echo -e "   --------------------------------------------"

# --- INITIAL INPUT ---
echo ""
log_info "Initialization..."

# 1. User
read -p "1. New Sudo Username [admin]: " SYS_USER
SYS_USER=${SYS_USER:-admin}

while true; do
    read -s -p "2. Password for $SYS_USER: " SYS_PASS
    echo ""
    read -s -p "   Confirm Password: " SYS_PASS_CONFIRM
    echo ""
    [ "$SYS_PASS" = "$SYS_PASS_CONFIRM" ] && break
    log_error "Passwords match failed. Try again."
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
echo -e "${YELLOW}Select Mode:${NC}"
echo -e "   [1] ${GREEN}AUTO${NC} (Recommended - Fast)"
echo -e "   [2] ${CYAN}MANUAL${NC} (Ask for each step)"
read -p "Choice [1]: " MODE
MODE=${MODE:-1}

# --- EXECUTION ENGINE ---
run_task() {
    local func=$1
    local desc=$2
    
    if [[ "$MODE" == "2" ]]; then
        echo ""
        read -p "Run: $desc? (y/n): " choice
        [[ "$choice" =~ ^[Yy]$ ]] && $func || log_warn "Skipped: $desc"
    else
        echo ""
        log_info "Running: $desc"
        $func
    fi
}

# --- TASKS ---

task_update() {
    apt-get update -qq && apt-get upgrade -y -qq
    apt-get install -y -qq ufw fail2ban auditd rkhunter curl vim sudo unattended-upgrades net-tools systemd-timesyncd
    log_success "System updated & Tools installed."
}

task_time() {
    timedatectl set-ntp on
    timedatectl set-timezone UTC
    log_success "Timezone set to UTC & NTP synced."
}

task_swap() {
    # Check RAM. If < 2GB and no swap, create 1GB swap.
    local ram=$(free -m | awk '/^Mem:/{print $2}')
    if [[ "$ram" -lt 2048 ]] && [[ -z $(swapon --show) ]]; then
        fallocate -l 1G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        log_success "Created 1GB Swap File (Low RAM detected)."
    else
        log_success "Swap check passed."
    fi
}

task_cleanup() {
    apt-get purge -y telnet rsh-client rsh-server talk yp-tools xinetd tftp-hpa vsftpd wu-ftpd > /dev/null 2>&1
    apt-get autoremove -y > /dev/null 2>&1
    log_success "Insecure packages removed."
}

task_user() {
    if ! id "$SYS_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$SYS_USER"
        echo "$SYS_USER:$SYS_PASS" | chpasswd
        usermod -aG sudo "$SYS_USER"
        log_success "User $SYS_USER created."
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
    
    # Base Config
    sed -i "s/#Port 22/Port $SSH_PORT/" $cfg
    sed -i "s/Port 22/Port $SSH_PORT/" $cfg
    if ! grep -q "^Protocol 2" $cfg; then echo "Protocol 2" >> $cfg; fi
    
    # Hardening
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' $cfg
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' $cfg
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' $cfg
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' $cfg
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' $cfg
    sed -i 's/#Banner none/Banner \/etc\/issue.net/' $cfg
    
    # Key Logic
    if [[ -n "$USER_SSH_KEY" ]]; then
        sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' $cfg
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' $cfg
    fi

    echo "NOTICE: Authorized Access Only." > /etc/issue.net
    log_success "SSH Hardened (Port: $SSH_PORT)."
}

task_firewall() {
    ufw --force reset > /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SSH_PORT"/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    echo "y" | ufw enable
    log_success "Firewall (UFW) enabled."
}

task_fail2ban() {
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
    log_success "Fail2Ban active."
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

task_shm() {
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
        mount -o remount /dev/shm
        log_success "Shared Memory (/dev/shm) secured."
    fi
}

# --- RUNNER ---
run_task task_update    "System Update & Tools"
run_task task_time      "NTP Time Sync"
run_task task_swap      "Smart Swap Creation"
run_task task_cleanup   "Remove Bloatware"
run_task task_user      "User Setup & Keys"
run_task task_ssh       "SSH Configuration"
run_task task_firewall  "Firewall Setup"
run_task task_fail2ban  "Fail2Ban Protection"
run_task task_network   "Network Hardening"
run_task task_shm       "Secure Shared Memory"

systemctl restart ssh

# --- FINISH ---
echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "   KEVLAR PROTECTION ENABLED"
echo -e "${GREEN}==========================================${NC}"
echo -e " User: ${YELLOW}$SYS_USER${NC}"
echo -e " Port: ${YELLOW}$SSH_PORT${NC}"
if [[ -n "$USER_SSH_KEY" ]]; then
    echo -e " Auth: ${GREEN}SSH KEY ONLY${NC}"
else
    echo -e " Auth: ${RED}PASSWORD${NC} (Add key later!)"
fi
echo -e "------------------------------------------"
echo -e "${RED}IMPORTANT:${NC} Do NOT close this session yet."
echo -e "Test connection in a NEW terminal:"
echo -e "${CYAN}ssh -p $SSH_PORT $SYS_USER@$(curl -s ifconfig.me)${NC}"
echo -e "=========================================="
