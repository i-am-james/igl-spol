Set-ExecutionPolicy RemoteSigned -Force

﻿# Silent function to check and install PolicyFileEditor module
function Silent-CheckAndInstall-PolicyFileEditorModule {
    $moduleName = "PolicyFileEditor"
    $moduleInstalled = Get-Module -ListAvailable -Name $moduleName

    if (-not $moduleInstalled) {
        Try {
            Install-Module -Name $moduleName -Force -Confirm:$false -ErrorAction Stop -Scope CurrentUser
        } Catch {
            Write-Host "✗ Failed to install PolicyFileEditor module." -ForegroundColor Red
            exit 1
        }
    }
    Import-Module $moduleName -Force -ErrorAction SilentlyContinue
}

# Define the path to the machine-level Group Policy (Registry.pol)
$policyPath = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"

# Define the key and value for "Enable Insecure Guest Logons"
$keyPath = "Software\Policies\Microsoft\Windows\LanmanWorkstation"
$valueName = "AllowInsecureGuestAuth"

# Function to check the current policy value and return its status
function Check-InsecureGuestLogonsPolicy {
    $currentValue = Get-PolicyFileEntry -Path $policyPath -Key $keyPath -ValueName $valueName

    if ($currentValue -eq $null) {
        Write-Host "✗ 'Enable Insecure Guest Logons' policy is not defined." -ForegroundColor Red
        return $false
    }
    elseif ($currentValue.Data -eq 1) {
        Write-Host "✓ 'Enable Insecure Guest Logons' is already enabled." -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "✗ 'Enable Insecure Guest Logons' is disabled." -ForegroundColor Red
        return $false
    }
}

# Function to enable the "Enable Insecure Guest Logons" policy
function Enable-InsecureGuestLogonsPolicy {
    Write-Host "Enabling 'Enable Insecure Guest Logons'..." -ForegroundColor Yellow

    # Set the policy to enable insecure guest logons (1 = Enabled)
    Set-PolicyFileEntry -Path $policyPath `
        -Key $keyPath `
        -ValueName $valueName `
        -Type DWord -Data 1

    Write-Host "✓ 'Enable Insecure Guest Logons' has been enabled." -ForegroundColor Green

    # Force a Group Policy update silently
    gpupdate /force | Out-Null
    Write-Host "Group Policy has been updated."
}

# New Function to apply all local security policy changes based on user confirmation, with minimal output
function Apply-SecurityPolicy {
    $userInput = Read-Host -Prompt "Do you want to apply all changes to the Local Security Policy? (Y/N)"
    
    if ($userInput -eq "Y") {
        Try {
            # Apply all changes at once with minimal output
            # 1. Network Security: LAN Manager Authentication Level
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 1 | Out-Null

            # 2. Disable Domain member: Require strong session key
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 0 | Out-Null

            # 3. Disable Domain member: Digitally encrypt or sign secure channel data (always)
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 0 | Out-Null

            # 4. Disable Domain member: Digitally sign secure channel data (when possible)
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 0 | Out-Null

            # 5. Disable Microsoft network client: Digitally sign communications (always)
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 | Out-Null

            # 6. Disable Microsoft network server: Digitally sign communications (always)
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0 | Out-Null

            # Apply security policy updates using secedit
            secedit /configure /db secedit.sdb /cfg %windir%\inf\defltbase.inf /overwrite /quiet | Out-Null

            # If everything succeeded, just output success
            Write-Host "✓ All security policy changes have been applied successfully." -ForegroundColor Green
        } Catch {
            Write-Host "✗ An error occurred while applying the security policy changes!" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Local Security Policy changes were skipped." -ForegroundColor Cyan
    }
}

# Calling functions
Silent-CheckAndInstall-PolicyFileEditorModule
if (-not (Check-InsecureGuestLogonsPolicy)) {
    Enable-InsecureGuestLogonsPolicy
} else {
    Write-Host "No changes were made, as the policy was already enabled." -ForegroundColor Cyan
}
Apply-SecurityPolicy | Out-Null

Write-Host "All checks are complete." -ForegroundColor Cyan
