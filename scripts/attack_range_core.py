import os
import shutil
import subprocess
import yaml
import requests
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

class AzureAttackRangeCore:
    """Core infrastructure management for Azure Attack Range"""
    
    def __init__(self, config, credential):
        self.config = config
        self.credential = credential
        self.network_client = NetworkManagementClient(credential, config['subscription_id'])
        self.compute_client = ComputeManagementClient(credential, config['subscription_id'])
    
    def update_ip_config(self):
        """Automatically update IP configuration in terraform files"""
        try:
            # Get current public IP
            response = requests.get('https://api.ipify.org?format=json')
            current_ip = f"{response.json()['ip']}/32"
            
            # Update terraform.tfvars
            tfvars_path = 'terraform/terraform.tfvars'
            
            # Check if allowed_ip variable exists in tfvars file
            if os.path.exists(tfvars_path):
                lines = []
                ip_config_found = False
                
                with open(tfvars_path, 'r') as f:
                    lines = f.readlines()
                
                with open(tfvars_path, 'w') as f:
                    for line in lines:
                        if 'allowed_ip' in line:
                            f.write(f'allowed_ip = "{current_ip}"\n')
                            ip_config_found = True
                        else:
                            f.write(line)
                    
                    # If allowed_ip wasn't found, add it
                    if not ip_config_found:
                        f.write(f'\nallowed_ip = "{current_ip}"\n')
            
            print(f"[+] Updated allowed IP to: {current_ip}")
            
            # Also ensure the variable exists in variables.tf
            variables_tf = 'terraform/variables.tf'
            if os.path.exists(variables_tf):
                with open(variables_tf, 'r') as f:
                    content = f.read()
                
                if 'allowed_ip' not in content:
                    with open(variables_tf, 'a') as f:
                        f.write('\n\nvariable "allowed_ip" {\n')
                        f.write('  description = "IP address allowed to connect to the Attack Range"\n')
                        f.write('  type        = string\n')
                        f.write('  default     = "0.0.0.0/0"\n')
                        f.write('}\n')
            
        except Exception as e:
            print(f"Warning: Could not update IP configuration: {e}")
            print("Continuing with existing configuration...")

    def build(self):
        """Build the complete attack range infrastructure"""
        print("[+] Building Azure Attack Range infrastructure...")
        
        # Update IP configuration before building
        self.update_ip_config()
        
        try:
            subprocess.run(["terraform", "-chdir=terraform", "init"], check=True)
            subprocess.run(["terraform", "-chdir=terraform", "apply", "-auto-approve"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error building infrastructure: Terraform exited with code {e.returncode}")
            return False
        except Exception as e:
            print(f"Error building infrastructure: {e}")
            return False

        print("[+] Infrastructure built successfully")

        if not self.create_ansible_inventory():
            print("Warning: Could not generate Ansible inventory; skipping Defender onboarding playbook.")
            return True

        self.run_defender_onboarding()
        return True

    def destroy(self):
        """Destroy the complete attack range infrastructure"""
        print("[+] Destroying Azure Attack Range infrastructure...")
        try:
            result = os.system(f"terraform -chdir=terraform destroy -auto-approve")
            if result != 0:
                print("Error: Terraform destroy failed")
                return False
            print("[+] Infrastructure destroyed successfully")
            return True
        except Exception as e:
            print(f"Error destroying infrastructure: {e}")
            return False

    def run_defender_onboarding(self):
        """Run the Defender for Endpoint onboarding playbook for Windows hosts."""

        script_path = self.config.get('defender_onboarding_script')
        if not script_path:
            print("Warning: 'defender_onboarding_script' is not set in attack-range.yml; skipping Defender onboarding.")
            return

        abs_script_path = os.path.abspath(script_path)

        if not os.path.exists(abs_script_path):
            print(f"Warning: Defender onboarding script not found at {abs_script_path}; skipping Defender onboarding.")
            return

        if shutil.which("ansible-playbook") is None:
            print("Warning: ansible-playbook is not available on PATH; skipping Defender onboarding.")
            return

        env = os.environ.copy()
        env['DEFENDER_ONBOARDING_SCRIPT'] = abs_script_path

        cmd = ["ansible-playbook", "-i", "playbooks/inventory.yml", "playbooks/windows_defender_endpoint.yml"]

        try:
            subprocess.run(cmd, check=True, env=env)
            print("[+] Microsoft Defender for Endpoint onboarding playbook completed.")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Ansible playbook exited with code {e.returncode}; Defender onboarding may be incomplete.")

    def update(self):
        """Update the infrastructure with new resources"""
        print("[+] Updating Azure Attack Range infrastructure...")
        
        # Update IP configuration before updating
        self.update_ip_config()
        
        try:
            result = os.system(f"terraform -chdir=terraform apply -auto-approve")
            if result != 0:
                print("Error: Terraform apply failed")
                return False
            print("[+] Infrastructure updated successfully")
            return True
        except Exception as e:
            print(f"Error updating infrastructure: {e}")
            return False

    def create_ansible_inventory(self):
        """Create Ansible inventory file with VM information"""
        print("[+] Creating Ansible inventory file...")
        
        admin_username = self.config.get('admin_username', 'azureuser')
        admin_password = self.config.get('admin_password')
        rg_name = self.config.get('resource_group', 'attack-range-rg')

        if not admin_password:
            print("Error: admin_password not found in configuration")
            return False

        inventory = {
            'all': {
                'children': {
                    'windows': {
                        'hosts': {},
                        'vars': {
                            'ansible_user': admin_username,
                            'ansible_password': admin_password,
                            'ansible_connection': 'winrm',
                            'ansible_winrm_server_cert_validation': 'ignore',
                            'ansible_port': '5985',
                            'ansible_winrm_scheme': 'http',
                            'ansible_winrm_transport': 'ntlm'
                        }
                    },
                    'linux': {
                        'hosts': {},
                        'vars': {
                            'ansible_user': 'kali',
                            'ansible_ssh_private_key_file': '~/.ssh/id_rsa',
                            'ansible_connection': 'ssh'
                        }
                    }
                }
            }
        }

        try:
            vms = self.compute_client.virtual_machines.list(rg_name)
            
            for vm in vms:
                try:
                    vm_name = vm.name
                    print(f"Processing VM: {vm_name}")

                    # Get network interface
                    network_interfaces = vm.network_profile.network_interfaces
                    if not network_interfaces:
                        continue

                    primary_nic_id = network_interfaces[0].id
                    nic_name = primary_nic_id.split('/')[-1]
                    nic = self.network_client.network_interfaces.get(rg_name, nic_name)
                    
                    if not nic.ip_configurations[0].public_ip_address:
                        continue

                    pip_id = nic.ip_configurations[0].public_ip_address.id
                    pip_name = pip_id.split('/')[-1]
                    pip = self.network_client.public_ip_addresses.get(rg_name, pip_name)
                    public_ip = pip.ip_address

                    print(f"Found IP {public_ip} for VM {vm_name}")

                    # Explicitly check for DC or workstation in the name
                    vm_name_lower = vm_name.lower()

                    if any(keyword in vm_name_lower for keyword in ["dc", "workstation", "win11", "server2025"]):
                        inventory['all']['children']['windows']['hosts'][vm_name] = {
                            'ansible_host': public_ip,
                            'ansible_winrm_operation_timeout_sec': 60,
                            'ansible_winrm_read_timeout_sec': 70,
                            'roles': ['defender_for_endpoint']
                        }
                    elif "kali" in vm_name_lower:
                        inventory['all']['children']['linux']['hosts'][vm_name] = {
                            'ansible_host': public_ip
                        }
                    
                except Exception as e:
                    print(f"Warning: Error processing VM {vm_name}: {str(e)}")
                    continue

            os.makedirs('playbooks', exist_ok=True)
            with open('playbooks/inventory.yml', 'w') as f:
                yaml.dump(inventory, f, default_flow_style=False)
            
            print("\nGenerated Inventory:")
            print(yaml.dump(inventory))
            
            return True

        except Exception as e:
            print(f"Error creating Ansible inventory: {str(e)}")
            return False

