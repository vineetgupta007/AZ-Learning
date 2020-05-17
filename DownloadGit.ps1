$url = "https://github.com/MicrosoftLearning/AZ-103-MicrosoftAzureAdministrator/archive/master.zip"
$output = "C:\Users\user\Desktop\master.zip"
$start_time = Get-Date

$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $output)

Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)" 