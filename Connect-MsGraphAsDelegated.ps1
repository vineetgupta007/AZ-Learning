# Connect to Microsoft Graph with delegated credentials (interactive login will popup).
function Connect-MsGraphAsDelegated {
    param (
        [string]$ClientID,
        [string]$ClientSecret
    )


    # Declarations.
    $Resource = "https://graph.microsoft.com"
    $RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"


    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    # UrlEncode the ClientID and ClientSecret and URL's for special characters.
    Add-Type -AssemblyName System.Web
    $ClientIDEncoded = [System.Web.HttpUtility]::UrlEncode($ClientID)
    $ClientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($ClientSecret)
    $ResourceEncoded = [System.Web.HttpUtility]::UrlEncode($Resource)
    $RedirectUriEncoded = [System.Web.HttpUtility]::UrlEncode($RedirectUri)

    # Function to popup Auth Dialog Windows Form.
    function Get-AuthCode {
        Add-Type -AssemblyName System.Windows.Forms
        $Form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 440; Height = 640 }
        $Web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 420; Height = 600; Url = ($Url -f ($Scope -join "%20")) }
        $DocComp = {
            $Global:uri = $Web.Url.AbsoluteUri        
            if ($Global:uri -match "error=[^&]*|code=[^&]*") { $Form.Close() }
        }

        $Web.ScriptErrorsSuppressed = $true
        $Web.Add_DocumentCompleted($DocComp)
        $Form.Controls.Add($Web)
        $Form.Add_Shown( { $Form.Activate() })
        $Form.ShowDialog() | Out-Null
        $QueryOutput = [System.Web.HttpUtility]::ParseQueryString($Web.Url.Query)
        $Output = @{ }

        foreach ($Key in $QueryOutput.Keys) {
            $Output["$Key"] = $QueryOutput[$Key]
        }
    }


    # Get AuthCode.
    $Url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$RedirectUriEncoded&client_id=$ClientID&resource=$ResourceEncoded&prompt=admin_consent&scope=$ScopeEncoded"
    Get-AuthCode


    # Extract Access token from the returned URI.
    $Regex = '(?<=code=)(.*)(?=&)'
    $AuthCode = ($Uri | Select-string -pattern $Regex).Matches[0].Value


    # Get Access Token.
    $Body = "grant_type=authorization_code&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecretEncoded&code=$AuthCode&resource=$Resource"
    $TokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token -Method Post -ContentType "application/x-www-form-urlencoded" -Body $Body -ErrorAction "Stop"


    $TokenResponse.access_token
}


# GET data from Microsoft Graph.
function Get-MsGraph {

    param (
        [parameter(Mandatory = $true)]
        $AccessToken,

        [parameter(Mandatory = $true)]
        $Uri
    )
	Write-Host $Uri
    # Check if authentication was successfull.
    if ($AccessToken) {
        # Format headers.
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }


        # Create an empty array to store the result.
        $QueryResults = @()


        # Invoke REST method and fetch data until there are no pages left.
        $Results = ""
        $StatusCode = ""

        do {
            try {
                $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"

                $StatusCode = $Results.StatusCode
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__

                if ($StatusCode -eq 429) {
                    Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                    Start-Sleep -Seconds 45
                }
                else {
                    Write-Error $_.Exception
                }
            }
        } while ($StatusCode -eq 429)

        if ($Results.value) {
            $QueryResults += $Results.value
        }
        else {
            $QueryResults += $Results
        }


        # Return the result.
        $QueryResults
    }
    else {
        Write-Error "No Access Token"
    }
}

# Authenticate to Microsoft Graph.
$AccessToken = Connect-MsGraphAsDelegated -ClientID "d6a55fb6-d094-44ae-ada8-93944b3badf8" -ClientSecret "DT5uNcKKMbkKeNE1pFG0SK5tlH8P3ksHQn253ZOKOFY="

$Uri = "https://graph.microsoft.com/v1.0/groups"
$ExcludeGroupId = (Get-MsGraph -AccessToken $AccessToken -Uri $Uri | Where-Object { $_.displayName -eq $ExcludeGroup }).id
#Get-MsGraph -AccessToken $AccessToken -Uri $Uri
Write-Host $ExcludeGroupId