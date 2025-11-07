#!/bin/bash
# MS-Attack-Range Dependency Fix Script
# This script resolves common issues with the Attack Range environment

echo "===== MS-Attack-Range Dependency Fix ====="
echo "This script will fix common issues with dependencies and configuration."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "[+] Detected Python version: $python_version"

major=$(echo $python_version | cut -d. -f1)
minor=$(echo $python_version | cut -d. -f2)

if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 7 ]); then
    echo "[!] Warning: Python 3.7+ is recommended. You're running $python_version"
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting. Please install Python 3.7 or newer."
        exit 1
    fi
fi

# Check if virtual environment exists and activate it
if [ -d "attack_range_env" ]; then
    echo "[+] Found existing virtual environment at ./attack_range_env"
    source attack_range_env/bin/activate
elif [ -d ".venv" ]; then
    echo "[+] Found existing virtual environment at ./.venv"
    source .venv/bin/activate
else
    echo "[+] Creating new virtual environment in ./attack_range_env"
    python3 -m venv attack_range_env
    source attack_range_env/bin/activate
fi

# Install/upgrade pip and wheel
echo "[+] Upgrading pip and installing wheel"
pip install --upgrade pip wheel

# Install core requirements
echo "[+] Installing core requirements from requirements.txt"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found. Installing essential packages manually."
    pip install azure-identity azure-mgmt-resource azure-mgmt-network azure-mgmt-compute PyYAML ansible requests
fi

# Ensure WinRM and its dependencies are installed
echo "[+] Ensuring WinRM and its dependencies are installed"
pip install pywinrm requests cryptography jmespath

# Create Ansible configuration file to disable deprecation warnings
echo "[+] Creating ansible.cfg to suppress warnings"
cat > ansible.cfg << EOF
[defaults]
deprecation_warnings = False
host_key_checking = False
retry_files_enabled = False
gather_subset = !hardware,!facter,!ohai

[ssh_connection]
pipelining = True
EOF

# Check if inventory file exists and fix if needed
if [ -f "playbooks/inventory.yml" ]; then
    echo "[+] Found existing inventory file"
    echo "[+] Validating inventory format..."
    
    # Check if windows and linux groups are properly defined
    if ! grep -q "windows:" playbooks/inventory.yml || ! grep -q "linux:" playbooks/inventory.yml; then
        echo "[!] Inventory file may be missing required groups. Backing up and regenerating."
        cp playbooks/inventory.yml playbooks/inventory.yml.bak
        
        # Create a basic inventory structure if regeneration fails
        cat > playbooks/inventory.yml << EOF
all:
  children:
    windows:
      hosts:
        attack-range-dc:
          ansible_host: REPLACE_WITH_DC_IP
          ansible_winrm_operation_timeout_sec: 60
          ansible_winrm_read_timeout_sec: 70
        attack-range-workstation:
          ansible_host: REPLACE_WITH_WORKSTATION_IP
          ansible_winrm_operation_timeout_sec: 60
          ansible_winrm_read_timeout_sec: 70
        attack-range-win11:
          ansible_host: REPLACE_WITH_WIN11_IP
          ansible_winrm_operation_timeout_sec: 60
          ansible_winrm_read_timeout_sec: 70
        attack-range-server2025:
          ansible_host: REPLACE_WITH_SERVER2025_IP
          ansible_winrm_operation_timeout_sec: 60
          ansible_winrm_read_timeout_sec: 70
      vars:
        ansible_connection: winrm
        ansible_password: YourSecurePassword123!AttackRange2024!
        ansible_port: '5985'
        ansible_user: azureuser
        ansible_winrm_scheme: http
        ansible_winrm_server_cert_validation: ignore
        ansible_winrm_transport: ntlm
    linux:
      hosts:
        attack-range-kali:
          ansible_host: REPLACE_WITH_KALI_IP
      vars:
        ansible_connection: ssh
        ansible_ssh_private_key_file: ~/.ssh/id_rsa
        ansible_user: kali
EOF
        echo "[!] Created template inventory file. Please update the IP addresses manually or run:"
        echo "    python attack-range.py update"
    fi
else
    echo "[!] No inventory file found. Please run:"
    echo "    python attack-range.py update"
fi

# Attempt to determine current public IP
echo "[+] Checking your current public IP address"
current_ip=$(curl -s ifconfig.me || curl -s icanhazip.com || curl -s api.ipify.org)

if [ -n "$current_ip" ]; then
    echo "[+] Your current public IP address appears to be: $current_ip"
    
    if [ -f "terraform/terraform.tfvars" ]; then
        current_allowed_ip=$(grep "allowed_ip" terraform/terraform.tfvars | cut -d'"' -f2 | cut -d'/' -f1)
        
        if [ "$current_allowed_ip" != "$current_ip" ]; then
            echo "[!] Your current IP ($current_ip) doesn't match the allowed IP in configuration ($current_allowed_ip)"
            read -p "Do you want to update the allowed IP in terraform.tfvars? (y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Create a backup
                cp terraform/terraform.tfvars terraform/terraform.tfvars.bak
                
                # Update the IP
                sed -i.bak "s/allowed_ip = \".*\"/allowed_ip = \"$current_ip\/32\"/" terraform/terraform.tfvars
                echo "[+] Updated allowed_ip in terraform.tfvars"
                echo "[+] You should run 'python attack-range.py update' to apply this change"
            fi
        else
            echo "[+] Your current IP matches the configured IP. No changes needed."
        fi
    else
        echo "[!] terraform.tfvars not found. Make sure you've configured your environment correctly."
    fi
else
    echo "[!] Could not determine your current IP address."
fi

# Check SSH key availability
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "[!] SSH private key not found at ~/.ssh/id_rsa"
    read -p "Do you want to generate a new SSH key pair? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
        echo "[+] New SSH key pair generated"
        echo "[+] Add this public key to terraform/terraform.tfvars:"
        echo "    ssh_public_key = \"$(cat ~/.ssh/id_rsa.pub)\""
    else
        echo "[!] Please ensure you have an SSH key configured or update the path in attack-range.yml"
    fi
fi

echo ""
echo "===== Dependency fixes completed ====="
echo ""
echo "Try running your command again. If you still encounter issues,"
echo "please check the troubleshooting guide or report the issue on GitHub."
echo ""
echo "Don't forget to activate your virtual environment before running commands:"
echo "  source attack_range_env/bin/activate  # Or source .venv/bin/activate"
echo ""
