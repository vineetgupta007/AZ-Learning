function Save-GitHubRepository
{
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Project,

        [Parameter()]
        [string]$Branch = 'master'
    )
	
	Write-Output $Owner

    $url = "https://github.com/$Owner/$Project/archive/$Branch.zip"
    $output = Join-Path $HOME "Desktop\${Project}-${Branch}_($(Get-Date -Format yyyyMMddHHmm)).zip"
    $start_time = Get-Date

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $output)

    Write-Host "Time taken: $((Get-Date).Subtract($start_time).TotalSeconds) second(s)" 
}

#Save-GitHubRepository MicrosoftLearning AZ-103-MicrosoftAzureAdministrator

Save-GitHubRepository javiersoriano sentinelascode

#Save-GitHubRepository -Owner $Owner -Project $Project