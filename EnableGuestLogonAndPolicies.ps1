Add-Type -AssemblyName System.Windows.Forms

function Install-NuGetIfNeeded {
    $nugetProvider = Get-PackageProvider -Name NuGet -Force

    if ($nugetProvider -eq $null) {
        Write-Host "Running Prechecks..." -ForegroundColor Yellow
        
        Try {
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -Confirm:$false -ErrorAction Stop | Out-Null
        } Catch {
        }
    }
}

function Silent-CheckAndInstall-PolicyFileEditorModule {
    $moduleName = "PolicyFileEditor"
    $moduleInstalled = Get-Module -ListAvailable -Name $moduleName

    if (-not $moduleInstalled) {
        # Display message before installation
        Write-Host "Installing Policy Editor. Please Wait..." -ForegroundColor Yellow
        Try {
            Install-Module -Name $moduleName -Force -Confirm:$false -ErrorAction Stop -Scope CurrentUser
        } Catch {
            Write-Host "✗ Failed to install PolicyFileEditor module." -ForegroundColor Red
            exit 1
        }
    }
    Import-Module $moduleName -Force -ErrorAction SilentlyContinue
}

$policyPath = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
$keyPath = "Software\Policies\Microsoft\Windows\LanmanWorkstation"
$valueName = "AllowInsecureGuestAuth"

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

function Enable-InsecureGuestLogonsPolicy {
    Write-Host "Enabling 'Enable Insecure Guest Logons'..." -ForegroundColor Yellow

    Set-PolicyFileEntry -Path $policyPath `
        -Key $keyPath `
        -ValueName $valueName `
        -Type DWord -Data 1

    Write-Host "✓ 'Enable Insecure Guest Logons' has been enabled." -ForegroundColor Green

    gpupdate /force | Out-Null
    Write-Host "Group Policy has been updated."
}

Install-NuGetIfNeeded

Silent-CheckAndInstall-PolicyFileEditorModule
if (-not (Check-InsecureGuestLogonsPolicy)) {
    Enable-InsecureGuestLogonsPolicy
} else {
    Write-Host "No changes were made, as the policy was already enabled." -ForegroundColor Cyan
}

Write-Host "All checks are complete." -ForegroundColor Cyan

[System.Windows.Forms.MessageBox]::Show("PioneerRx should now launch.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
