function Get-GraphApiResult {

    param (
        [parameter(Mandatory = $true)]
        $ClientID,

        [parameter(Mandatory = $true)]
        $ClientSecret,

        [parameter(Mandatory = $true)]
        $TenantName,

        [parameter(Mandatory = $true)]
        $Uri
    )


    # Graph API URLs.
    $LoginUrl = "https://login.microsoft.com"
    $RresourceUrl = "https://graph.microsoft.com"
    

    # Compose REST request.
    $Body = @{ grant_type = "client_credentials"; resource = $RresourceUrl; client_id = $ClientID; client_secret = $ClientSecret }
    $OAuth = Invoke-RestMethod -Method Post -Uri $LoginUrl/$TenantName/oauth2/token?api-version=1.0 -Body $Body
    

    # Check if authentication was successfull.
    if ($OAuth.access_token) {
        # Format headers.
        $HeaderParams = @{
            'Content-Type'  = "application\json"
            'Authorization' = "$($OAuth.token_type) $($OAuth.access_token)"
        }


        # Create an empty array to store the result.
        $QueryResults = @()


        # Invoke REST method and fetch data until there are no pages left.
        do {
            $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"

            if ($Results.value) {
                $QueryResults += $Results.value
            } else {
                $QueryResults += $Results
            }

            $uri = $Results.'@odata.nextlink'
        } until (!($uri))


        # Return the result.
        $QueryResults
    }
    else {
        Write-Error "No Access Token"
    }
}

#Get-GraphApiResult -ClientID "cc85fc05-64fc-489b-9ca3-918e9ca62320" -ClientSecret "W8X5wrmSm9TzBlRn6nHWniRyALymReBvi2YjsuCtUVQ=" -TenantName "vineetgupta2020outlook.onmicrosoft.com" -Uri "https://graph.microsoft.com/v1.0/users"

Get-GraphApiResult -ClientID "fbab34f2-ffbd-4cf0-ad40-46cc0fca7b5f" -ClientSecret "J4EOAIJnbbUVCE0FmDw7LPd4GEo1FpcfRGObTgaYgL4=" -TenantName "vineetgupta2020outlook.onmicrosoft.com" -Uri "https://graph.microsoft.com/v1.0/groups"