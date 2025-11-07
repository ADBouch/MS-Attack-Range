# Microsoft Defender for Endpoint Onboarding

Place the Microsoft Defender for Endpoint onboarding PowerShell script you obtain from the Microsoft Defender portal in this directory.

The build workflow will copy the script to the Windows virtual machines and execute it via Ansible after Terraform provisioning completes. By default, the automation looks for a file named `MicrosoftDefenderOnboarding.ps1` in this folder; you can adjust the path with the `defender_onboarding_script` setting in `attack-range.yml`.
