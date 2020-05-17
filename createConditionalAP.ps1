[cmdletbinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage="customer.onmicrosoft.com",
            Position=1
        )][string] $TenantDomain,
        [Parameter(
            Mandatory = $true,
            HelpMessage="Group to exclude from policies",
            Position=2
        )][string] $ExcludeGroup
    )

#region Condition Access JSON
$ConditionalAccessPolicies = @(@"
{
    "displayName": "[BLOCK] - Legacy Authentication",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
            ],
        },
        "applications": {
            "includeApplications": [
                "All"
            ]
        },
        "clientAppTypes": [
            "easSupported",
            "easUnsupported",
            "other"
        ],
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ]
    }
}
"@
, @"
{
    "displayName": "[BLOCK] - Unsafe Countries",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ]
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted",
                "00000000-0000-0000-0000-000000000000"
            ]
        },
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ]
    }
}
"@
, @"
{
    "displayName": "[BLOCK] - Guest Access",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "GuestsOrExternalUsers"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [
                "925eb0d0-da50-4604-a19f-bd8de9147958",
                "00000003-0000-0ff1-ce00-000000000000",
                "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3"
            ]
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ]
    }
}
"@
, @"
{
    "displayName": "[MFA] - Untrusted context",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted"
            ]
        },
        "deviceStates": {
            "includeStates": [
                "All"
            ],
            "excludeStates": [
                "Compliant",
                "DomainJoined"
            ]
        }

    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa",
            "compliantDevice"
        ]
    }
}
"@
, @"
{
    "displayName": "[MFA] - Admin Roles",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeRoles": [
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                "e3973bdf-4987-49ae-837a-ba8e231c7286",
                "7495fdc4-34c4-4d15-a289-98788ce399fd",
                "aaf43236-0c0d-4d5f-883a-6955382ac081",
                "3edaf663-341e-4475-9f94-5c398ef6c070",
                "6e591065-9bad-43ed-90f3-e9424366d2f0",
                "0f971eea-41eb-4569-a71e-57bb8a3eff1e",
                "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                "158c047a-c907-4556-b7ef-446551a6b5f7",
                "7698a772-787b-4ac8-901f-60d6b08affd2",
                "17315797-102d-40b4-93e0-432062caca18",
                "e6d1a23a-da11-4be4-9570-befc86d067a7",
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4",
                "44367163-eba1-44c3-98af-f5787879f96a",
                "29232cdf-9323-42fd-ade2-1d097af3e4de",
                "be2f45a1-457d-42af-a067-6ec1fa63bc45",
                "62e90394-69f5-4237-9190-012177145e10",
                "fdd7a751-b60b-444a-984c-02652fe8fa1c",
                "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                "3a2c62db-5318-420d-8d74-23affee5d9d5",
                "74ef975b-6605-40af-a5d2-b9539d836353",
                "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
                "2b745bdf-0803-4d80-aa65-822c4493daac",
                "966707d0-3269-4727-9be2-8c3a10f19b9d",
                "a9ea8996-122f-4c74-9520-8edcd192826c",
                "11648597-926c-4cf3-9c36-bcebb0ba8dcc",
                "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                "0964bb5e-9bdb-4d7b-ac29-58e794862a40",
                "194ae4cb-b126-40b2-bd5b-6091b380977d",
                "f023fd81-a637-4b56-95fd-791ac0226033",
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                "75941009-915a-4869-abe7-691bff18279e",
                "baf37b3a-610e-45da-9e62-d9d1e5e8914b",
                "69091246-20e8-4a56-aa4d-066075b2a7a8",
                "fe930be7-5e62-47db-91af-98c3a49a38b1"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ]
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted"
            ]
        },
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ]
    }
}
"@)
#endregion

function Get-MsGraph {
    param (
        [parameter(Mandatory = $true)]
        $AccessToken,
        [parameter(Mandatory = $true)]
        $Uri
    )

    $HeaderParams = @{
        'Content-Type'  = "application\json"
        'Authorization' = "Bearer $AccessToken"
    }

    $ResultArray = @()
    $Results = ""
    $StatusCode = ""

        do {
            try {
                $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
                $StatusCode = $Results.StatusCode
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__

                if ($StatusCode -eq 429) {
                    Write-Warning "Microsoft is throttling.. waiting 30 seconds."
                    Start-Sleep -Seconds 30
                } else {
                    Write-Error $_.Exception
                }
            }
        } while ($StatusCode -eq 429)
            if ($Results.value) {
                $ResultArray += $Results.value
            } else {
                $ResultArray += $Results
            }

        $ResultArray
}

function Post-MsGraph {
    param (
        [parameter(Mandatory = $true)]
        $AccessToken,
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $true)]
        $Body
    )

    $HeaderParams = @{
        'Content-Type'  = "application\json"
        'Authorization' = "$($OAuth.token_type) $($AccessToken)"
    }

    $ResultArray = @()
    $Results = ""
    $StatusCode = ""

        do {
            try {
                $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "POST" -ContentType "application/json" -Body $Body
                $StatusCode = $Results.StatusCode
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__

                if ($StatusCode -eq 429) {
                    Write-Warning "Microsoft is throttling.. waiting 30 seconds."
                    Start-Sleep -Seconds 30
                } else {
                    Write-Error $_.Exception
                }
            }
        } while ($StatusCode -eq 429)
            if ($Results.value) {
                $ResultArray += $Results.value
            } else {
            $ResultArray += $Results
        }
    $ResultArray  
}

#region connect to Microsoft Graph
Function Connect-toGraph {
    $ClientID = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx'
    $tenantID = (Invoke-WebRequest https://login.windows.net/$TenantDomain/.well-known/openid-configuration|ConvertFrom-Json).token_endpoint.Split('/')[3]
    $resource = "https://graph.microsoft.com/"

    $requestBody = @{ 
        resource  = $resource
        client_id = $clientId
    }

    ## -- Get OAuth Code --##
    $codeRequest = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/devicecode" -Body $requestBody
    $OAuthCode = ($codeRequest.message -split "code " | Select-Object -Last 1) -split " to authenticate."
    Write-Host
    Write-Host "`n$($codeRequest.message)"
    Write-Host "Webpage will automatically open - press CTRL + V to past in code!" -ForegroundColor Green
    Write-Host
    Start-Sleep -Seconds 5
    Set-Clipboard -Value $OAuthCode
    Start "https://microsoft.com/devicelogin"

    $tokenBody = @{
        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        code       = $codeRequest.device_code
        client_id  = $clientId
    }

    ## -- Get AccessToken --##
    while ([string]::IsNullOrEmpty($tokenRequest.access_token)) {
        $tokenRequest = try {
            Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Body $tokenBody
        } catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($errorMessage.error -ne "authorization_pending") {
                throw
            }
        }
    }
    $tokenRequest.access_token
}

## -- Get Access Token -- ##
$AccessToken = Connect-toGraph
#endregion

if ($AccessToken) {
    ## Get the Exclude Group ID
    $Uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$ExcludeGroup'"
    $ExcludeGroupId = (Get-MsGraph -AccessToken $AccessToken -Uri $Uri | Where-Object { $_.displayName -eq $ExcludeGroup }).id

    $Uri = 'https://graph.microsoft.com/beta/conditionalAccess/policies'
    foreach ($Policy in $ConditionalAccessPolicies) {
        $Policy | Out-Null
        
        try {
            Post-MsGraph -AccessToken $AccessToken -Uri $Uri -Body $Policy
        } catch {
            Write-Host "Woops!" -ForegroundColor Red
        }
    }
} else {
    Write-Host "Not connected to Microsoft Graph" -ForegroundColor Red
}