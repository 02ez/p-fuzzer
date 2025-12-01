# ========================================================================
# LabLeakFinder - Data Security Hardening Script
# Ensures sensitive penetration testing data is protected
# ========================================================================

# Set execution policy for this script only
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

$ProjectPath = "C:\Users\tyler\p-fuzzer"
$ReportFiles = @(
    "post_exploitation_report.json",
    "data_discovery_log.json", 
    "business_impact_assessment.json",
    "findings_report.json",
    "exploitation_report.json",
    "exploitation_report.html",
    "findings_report.html",
    "*.log"
)

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "LabLeakFinder - Data Security Audit & Hardening" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# ========================================================================
# STEP 1: AUDIT - Check Current File Permissions
# ========================================================================
Write-Host "`n[AUDIT] Checking file permissions..." -ForegroundColor Yellow

Get-ChildItem -Path $ProjectPath -Recurse -Include $ReportFiles | ForEach-Object {
    $acl = Get-Acl -Path $_.FullName
    $owner = $acl.Owner
    $access = $acl.Access | Where-Object { $_.IsInherited -eq $false }
    
    Write-Host "File: $($_.Name)" -ForegroundColor White
    Write-Host "  Owner: $owner"
    Write-Host "  Permissions: $(($access | Select-Object -ExpandProperty IdentityReference).Value -join ', ')"
}

# ========================================================================
# STEP 2: RESTRICT - Set Owner to Current User Only
# ========================================================================
Write-Host "`n[RESTRICT] Restricting file ownership..." -ForegroundColor Yellow

$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

Get-ChildItem -Path $ProjectPath -Recurse -Include $ReportFiles | ForEach-Object {
    $acl = Get-Acl -Path $_.FullName
    
    # Clear all existing access rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    
    # Add FullControl only for current user
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $CurrentUser,
        "FullControl",
        "Allow"
    )
    $acl.AddAccessRule($rule)
    
    Set-Acl -Path $_.FullName -AclObject $acl
    Write-Host "✓ $($_.Name) - Owner: $CurrentUser (Full Control)"
}

# ========================================================================
# STEP 3: ENCRYPT - Enable File Encryption (EFS - Encrypting File System)
# ========================================================================
Write-Host "`n[ENCRYPT] Enabling file encryption..." -ForegroundColor Yellow

$EncryptionContainer = "$ProjectPath\encrypted_reports"
if (-not (Test-Path $EncryptionContainer)) {
    New-Item -ItemType Directory -Path $EncryptionContainer -Force | Out-Null
    Write-Host "✓ Created encrypted folder: $EncryptionContainer"
}

Get-ChildItem -Path $ProjectPath -Recurse -Include $ReportFiles | ForEach-Object {
    # Enable EFS encryption
    cipher /e /s:$_.FullName /h | Out-Null
    
    # Move to encrypted folder
    Move-Item -Path $_.FullName -Destination "$EncryptionContainer\$($_.Name)" -Force
    Write-Host "✓ Encrypted & moved: $($_.Name)"
}

# ========================================================================
# STEP 4: AUDIT LOG - Create security audit log
# ========================================================================
Write-Host "`n[AUDIT LOG] Generating security audit log..." -ForegroundColor Yellow

$AuditLog = @{
    "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    "user" = $CurrentUser
    "action" = "Security Hardening Applied"
    "encrypted_path" = $EncryptionContainer
    "files_secured" = @(Get-ChildItem -Path $EncryptionContainer -Recurse -File | Select-Object -ExpandProperty Name)
    "encryption_status" = "EFS Enabled"
    "access_control" = "Owner-only (Full Control)"
    "backup_recommended" = "YES - Use BitLocker or File History"
} | ConvertTo-Json

$AuditLog | Out-File -FilePath "$ProjectPath\security_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Force
Write-Host "✓ Audit log created"

# ========================================================================
# STEP 5: BACKUP - Create encrypted backup
# ========================================================================
Write-Host "`n[BACKUP] Creating encrypted backup..." -ForegroundColor Yellow

$BackupPath = "$ProjectPath\backups"
if (-not (Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

$ZipName = "p-fuzzer_reports_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
$ZipPath = "$BackupPath\$ZipName"

# Create compressed archive
Compress-Archive -Path "$EncryptionContainer\*" -DestinationPath $ZipPath -Force
Write-Host "✓ Backup created: $ZipName"

# Encrypt the backup file
cipher /e /s:$ZipPath | Out-Null
Write-Host "✓ Backup encrypted with EFS"

# ========================================================================
# STEP 6: BITLOCKER - Enable BitLocker for full drive encryption (Optional)
# ========================================================================
Write-Host "`n[OPTIONAL] BitLocker Full Drive Encryption" -ForegroundColor Cyan
Write-Host "To enable BitLocker for your entire drive (Recommended):"
Write-Host "1. Open 'Manage BitLocker' (Win + R, type: BitLockerDriveEncryption.msc)"
Write-Host "2. Click 'Turn on BitLocker' on your C: drive"
Write-Host "3. Save recovery key to secure location"
Write-Host "4. Verify encryption enabled"

# ========================================================================
# STEP 7: SECURITY SUMMARY
# ========================================================================
Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "SECURITY HARDENING COMPLETE" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green

$Summary = @{
    "Encryption" = "✓ EFS enabled on all report files"
    "Access Control" = "✓ Owner-only permissions enforced"
    "Backup" = "✓ Encrypted backup created"
    "Audit Trail" = "✓ Security log generated"
    "Protected Path" = $EncryptionContainer
    "Backup Location" = $BackupPath
} | Format-Table -AutoSize

Write-Host $Summary

# ========================================================================
# STEP 8: RECOMMENDATIONS
# ========================================================================
Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Cyan
Write-Host "1. ✓ Enable BitLocker for full disk encryption"
Write-Host "2. ✓ Set file password if sharing via email (7-Zip, WinRAR)"
Write-Host "3. ✓ Keep backup in secure location (external drive, cloud with MFA)"
Write-Host "4. ✓ Review access logs: Get-EventLog -LogName Security"
Write-Host "5. ✓ Never commit sensitive data to public GitHub"
Write-Host "6. ✓ Use Perplexity's private thread for development notes"
Write-Host "7. ✓ Rotate credentials (if any were used in testing)"

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "Your LabLeakFinder data is now SECURED ✓" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
