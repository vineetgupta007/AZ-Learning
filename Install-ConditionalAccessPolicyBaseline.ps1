<#
.NAME
    Install-ConditionalAccessPolicyBaseline.ps1
    
.SYNOPSIS
    This script is a proof of concept on how you can use PowerShell and Microsoft Graph to automatically deploy your Conditional Access policies in Azure AD.

.DESCRIPTION
    This script uses Microsoft Graph to automatically create Conditional Access policies based on a JSON representation of each policy (have a look at the $ConditionalAccessPolicies array in this script).

    All policies are created in a disabled state. You can then change them to Report-only or Enabled in the Azure portal.

    You can find the full details on how to format the JSON in the Microsoft Graph documentation:
    https://docs.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-beta

    The following Microsoft Graph API permissions are required for this script to work:
        Policy.ReadWrite.ConditionalAccess
        Policy.Read.All
        Directory.Read.All
        Agreement.Read.All
        Application.Read.All
    
    Also, the user running this script (the one who signs in when the authentication pops up) must have the appropriate permissions in Azure AD.

    Make sure you configure the variables under Declarations before you run this script.

    As a best practice you should always have a Azure AD security group with break glass accounts excluded from all Conditional Access policies. Specify the groups displayname with the $ExcludeGroup variable.

    The policy design in this proof of concept contains a Terms of Use policy. Make sure there is a Terms of Use object created in Azure AD before you run this script. Then set the $TermsOfUse variable in this script to its displayname in Azure AD.

    The policy design in this proof of concept will create a policy blocking all countries not explicitly allowed in a named location whitelist. Make sure there is an named location in Azure AD containing your organizations allowed countries. Set the $AllowedCountries variable to its displayname.
    
.PARAMETERS
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).
    
.INPUTS
    None

.OUTPUTS
    None

.NOTES
    Version:        1.1
    Author:         Daniel Chronlund
    Creation Date:  2020-04-21
  
.EXAMPLE
    .\Install-ConditionalAccessPolicyBaseline.ps1
#>

# ----- [Initialisations] -----

# Set Error Action - Possible choices: Stop, SilentlyContinue
$ErrorActionPreference = "Stop"

# ----- [Declarations] -----

# Client ID for the Azure AD application with Microsoft Graph permissions.
$ClientID = 'd6a55fb6-d094-44ae-ada8-93944b3badf8'

# Client secret for the Azure AD application with Microsoft Graph permissions.
$ClientSecret = 'DT5uNcKKMbkKeNE1pFG0SK5tlH8P3ksHQn253ZOKOFY='

# The displayname of the Azure AD group excluded from all CA policies, containing organization break glass accounts.
$ExcludeGroup = 'Excluded from CA'

# The displayname of the organizations Terms of Use in Azure AD.
$TermsOfUse = 'Terms of Use'

# The displayname of the Allowed countries named location containing whitlisted countries allowed to connect to Azure AD.
$AllowedCountries = 'Allowed countries'

# ----- [Functions] -----

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


# POST data to Microsoft Graph.
function Post-MsGraph {

    param (
        [parameter(Mandatory = $true)]
        $AccessToken,

        [parameter(Mandatory = $true)]
        $Uri,

        [parameter(Mandatory = $true)]
        $Body
    )


    # Check if authentication was successfull.
    if ($AccessToken) {
        # Format headers.
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "$($OAuth.token_type) $($AccessToken)"
        }


        # Create an empty array to store the result.
        $QueryResults = @()


        # Invoke REST method and fetch data until there are no pages left.
        $Results = ""
        $StatusCode = ""

        do {
            try {
                $Uri
                $Body
                $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "POST" -ContentType "application/json" -Body $Body

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

# ----- [Execution] -----

# Authenticate to Microsoft Graph.
$AccessToken = Connect-MsGraphAsDelegated -ClientID $ClientID -ClientSecret $ClientSecret


# Get group id of exclude group.
$Uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$ExcludeGroup'"
$ExcludeGroupId = (Get-MsGraph -AccessToken $AccessToken -Uri $Uri | Where-Object { $_.displayName -eq $ExcludeGroup }).id


# Get Terms of Use id (requires API permission Agreement.Read.All).
$Uri = 'https://graph.microsoft.com/beta/agreements'
$TermsOfUseId = (Get-MsGraph -AccessToken $AccessToken -Uri $Uri | Where-Object { $_.displayName -eq $TermsOfUse }).id


# Get Allowed countries named location (requires permission Policy.ReadWrite.ConditionalAccess).
$Uri = 'https://graph.microsoft.com/beta/conditionalAccess/namedLocations'
$AllowedCountriesId = (Get-MsGraph -AccessToken $AccessToken -Uri $Uri | Where-Object { $_.displayName -eq $AllowedCountries }).id


# Array of JSON representations of all the Conditonal Access policies.
$ConditionalAccessPolicies = @(@"
{
    "displayName": "BLOCK - Legacy Authentication",
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
        ]
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
    "displayName": "BLOCK - High-Risk Sign-Ins",
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
        "signInRiskLevels": [
            "high"
        ]
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
    "displayName": "BLOCK - Countries not Allowed",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
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
                "$AllowedCountriesId"
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
	"displayName": "BLOCK - Explicitly Blocked Cloud Apps",
	"state": "enabledForReportingButNotEnforced",
	"conditions": {
		"users": {
			"includeUsers": [
				"All"
			],
			"excludeGroups": [
				"$ExcludeGroupId"
			]
		},
		"applications": {
			"includeApplications": [
                "None"
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
	"displayName": "GRANT - Terms of Use",
	"state": "enabledForReportingButNotEnforced",
	"conditions": {
		"users": {
			"includeUsers": [
				"All"
			],
			"excludeGroups": [
				"$ExcludeGroupId"
			]
		},
		"applications": {
			"includeApplications": [
				"All"
			]
		}
	},
	"grantControls": {
		"operator": "OR",
		"termsOfUse": [
			"$TermsOfUseId"
		]
	}
}
"@
, @"
{
    "displayName": "GRANT - Browser Access",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ]
        },
        "clientAppTypes": [
            "browser"
        ]
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ]
    }
}
"@
, @"
{
	"displayName": "SESSION - Block Unmanaged Browser File Downloads",
	"state": "enabledForReportingButNotEnforced",
	"conditions": {
		"users": {
			"includeUsers": [
				"All"
			],
			"excludeGroups": [
				"$ExcludeGroupId"
			]
		},
		"applications": {
			"includeApplications": [
				"00000002-0000-0ff1-ce00-000000000000",
				"00000003-0000-0ff1-ce00-000000000000"
			]
		},
		"clientAppTypes": [
			"browser"
		],
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
	"sessionControls": {
		"applicationEnforcedRestrictions": {
            "isEnabled": true
        }
	}
}
"@
, @"
{
	"displayName": "GRANT - Intune Enrollment",
	"state": "enabledForReportingButNotEnforced",
	"conditions": {
		"users": {
			"includeUsers": [
				"All"
			],
			"excludeGroups": [
				"$ExcludeGroupId"
			]
		},
		"applications": {
			"includeApplications": [
                "0000000a-0000-0000-c000-000000000000",
                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
			]
		},
		"clientAppTypes": [
			"modern"
		]
	},
	"grantControls": {
		"operator": "OR",
		"builtInControls": [
			"mfa"
		]
	}
}
"@
, @"
{
	"displayName": "GRANT - Mobile Device Access",
	"state": "disabled",
	"conditions": {
		"users": {
			"includeUsers": [
				"All"
			],
			"excludeGroups": [
				"$ExcludeGroupId"
			]
		},
		"applications": {
			"includeApplications": [
				"All"
			],
			"excludeApplications": [
				"0000000a-0000-0000-c000-000000000000",
                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
			]
		},
		"platforms": {
			"includePlatforms": [
				"iOS",
                "android"
			]
		},
		"clientAppTypes": [
			"modern"
		]
	},
	"grantControls": {
		"operator": "AND",
		"builtInControls": [
			"mfa",
			"compliantDevice",
			"approvedApplication"
		]
	}
}
"@
, @"
{
    "displayName": "GRANT - Windows Device Access",
    "state": "disabled",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [
                "0000000a-0000-0000-c000-000000000000",
                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
            ]
        },
        "platforms": {
            "includePlatforms": [
                "windows"
            ]
        },
        "clientAppTypes": [
            "modern"
        ]
    },
    "grantControls": {
        "operator": "AND",
        "builtInControls": [
            "mfa",
            "domainJoinedDevice",
            "compliantDevice"
        ]
    }
}
"@
, @"
{
    "displayName": "GRANT - Mac Device Access",
    "state": "disabled",
    "conditions": {
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [
                "0000000a-0000-0000-c000-000000000000",
                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
            ]
        },
        "platforms": {
            "includePlatforms": [
                "macOS"
            ]
        },
        "clientAppTypes": [
            "modern"
        ]
    },
    "grantControls": {
        "operator": "AND",
        "builtInControls": [
            "mfa",
            "compliantDevice"
        ]
    }
}
"@
, @"
{
    "displayName": "GRANT - Guest Access",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "GuestsOrExternalUsers"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
            ]
        },
        "applications": {
            "includeApplications": [
                "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",
                "00000003-0000-0ff1-ce00-000000000000",
                "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3",
                "00000002-0000-0ff1-ce00-000000000000",
                "00000004-0000-0ff1-ce00-000000000000"
            ]
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ]
    }
}
"@
, @"
{
    "displayName": "BLOCK - Guest Access",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {
            "includeUsers": [
                "GuestsOrExternalUsers"
            ],
            "excludeGroups": [
                "$ExcludeGroupId"
            ]
        },
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [
                "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",
                "00000003-0000-0ff1-ce00-000000000000",
                "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3",
                "00000002-0000-0ff1-ce00-000000000000",
                "00000004-0000-0ff1-ce00-000000000000"
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
"@)


# URI for creating Conditional Access policies.
$Uri = 'https://graph.microsoft.com/beta/conditionalAccess/policies'


# Loop through the array of JSON representations of Conditional Access policies and create them.
foreach ($Policy in $ConditionalAccessPolicies) {
    # Output the JSON body.
    $Policy

    # Create conditional access policy (requires API permission Policy.ReadWrite.ConditionalAccess).
    try {
        Post-MsGraph -AccessToken $AccessToken -Uri $Uri -Body $Policy
    } catch {
        Write-Error -Message $_.Exception.Message -ErrorAction Continue
    }
}

# ----- [End] -----