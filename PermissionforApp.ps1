$AADModule = Get-Module -Name "AzureAD" -ListAvailable
## AzureADPreview Installed?
if ($AADModule -eq $null) {
    $AADModule = Get-Module -Name "AzureADPreview" -ListAvailable
}
## No AzureAD or AzureADPreview installed?
If ($AADModule -eq $null) {
    Write-Host "AzureAD PowerShell Module not installed." -ForegroundColor Red
    Write-Host "Install with 'Install-Module -Name AzureAD'" -ForegroundColor Red
	
	Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser
}

Try {
    $connect = Get-AzureADTenantDetail
} Catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
    Connect-AzureAD | Out-Null
}
$PermissionName = Read-Host "Enter the permission name found on docs.com"
$RoleID = (Get-AzureADServicePrincipal -filter "DisplayName eq 'Microsoft Graph'").OAuth2Permissions | Where-Object {$_.Value -eq $PermissionName}
if ($RoleID) {
    $RoleID
} else {
    Write-Host "Role not found!" -ForegroundColor Magenta
}