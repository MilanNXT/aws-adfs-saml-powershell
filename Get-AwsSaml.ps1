[CmdletBinding(DefaultParameterSetName='s2')]
[Parameter()]
Param(
    [string]$RoleArn = '',
    [string]$ProfileName = "saml",
    [string]$ProfileLocation = "$($HOME)\.aws\credentials",
    [string]$IdpEndpoint = 'https://sts.contoso.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices',
    [switch]$Force = $false,
    [switch]$SetEnvVar = $false,
    [switch]$SetSharedCred = $true,
    [Parameter (ParameterSetName = 's1', Mandatory = $false)][string]$UserName = '',
    [Parameter (ParameterSetName = 's1', Mandatory = $false)][string]$Password = '',
    [Parameter (ParameterSetName = 's2', Mandatory = $false)][System.Management.Automation.PSCredential]$Credential
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
Write-Verbose "Selected profile: [$ProfileName]"
Write-Verbose "Selected profile location: [$ProfileLocation]"
if (![string]::IsNullOrEmpty($RoleArn)) {
    Write-Verbose "Pre-Selected role: [$RoleArn]"
}

#check Nuget
if ([string]::isnullorempty((Get-PackageProvider -ListAvailable -verbose:$false | select Name, Version | where {($_.Name -eq 'NuGet') -and ($_.Version -eq '2.8.5.208')}))) {
    Write-Verbose -Message "Installing NuGet 2.8.5.208"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -verbose:$false| Out-Null
    Import-PackageProvider -Name 'NuGet' -Force -verbose:$false | Out-Null
} else {
    Write-Verbose -Message "NuGet 2.8.5.208 allready installed..."
}

# check PSGallery
$psgall = Get-PackageSource -Name 'PSGallery' -verbose:$false -ErrorAction SilentlyContinue
if ([string]::isnullorempty($psGall) -or ($psgall.ProviderName -ne 'PowerShellGet') -or (!$psgall.IsRegistered) -or (!$psgall.IsTrusted)) {
    Write-Verbose -Message "Registering PSGallery ..."
    if (![string]::isnullorempty($psgall)) {
        $psgall = Register-PackageSource -Name 'PSGallery' -ProviderName 'PowerShellGet' -Force -Trusted -verbose:$false -ErrorAction SilentlyContinue | Out-Null
    } else {
        $psgall = Register-PackageSource -Name 'PSGallery' -Location 'https://www.powershellgallery.com/api/v2/' -ProviderName 'PowerShellGet' -verbose:$false -ErrorAction SilentlyContinue -Force
    }
    if (!$psgall.IsTrusted) {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted' -ErrorAction SilentlyContinue -verbose:$false | Out-Null
        Set-PackageSource -Name 'PSGallery' -Trusted -Force -ErrorAction SilentlyContinue -verbose:$false | Out-Null
    }
} else {
    Write-Verbose -Message "PSGallery allready registered ..."
}

if(-Not (Get-Module AWSPowershell -ListAvailable -verbose:$false)) {
    Write-Verbose "AWSPowershell not found. Installing..."
    Install-Module AWSPowershell -Scope CurrentUser -Force -verbose:$false | Out-Null
}

Import-Module AWSPowerShell -verbose:$false

if (!$force) {
    try {
        Get-S3Bucket -ProfileName $ProfileName | Out-Null
        Write-Verbose "Valid credential are still available. No need to refresh. Use -Force to force resfresh"
        exit
    } catch {
        Write-Verbose "Credentials expired, processing to refresh"
    }
}

$WebRequestParams=@{ #Initialize parameters object
    Uri = $IdpEndpoint
    Method = 'POST'
    ContentType = 'application/x-www-form-urlencoded'
    SessionVariable = 'WebSession'
    UseBasicParsing = $true
}

# set credentials for web request
$ParameterSetName = $PSCmdlet.ParameterSetName
if ([string]::IsNullOrEmpty($Credential)) {
    $ParameterSetName = 's1'
}
if ($ParameterSetName -eq 's1') {
    if ([string]::IsNullOrEmpty($UserName) -or [string]::IsNullOrEmpty($Password)) {
        if ([string]::IsNullOrEmpty($UserName)) {
            $UserName = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).Identities.Name
        }
        #$Credential = Get-Credential -UserName $UserName -Message "Enter the domain credentials:"
        $upn = (Read-Host -Prompt "Username [$UserName]")
        if (![string]::IsNullOrEmpty($upn)) { $UserName = $upn}
        $PasswordSecured = (Read-Host -Prompt "Password" -AsSecureString)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecured))
        $Credential = [System.Management.Automation.PSCredential]::new($UserName, $PasswordSecured)
    }
} elseif ($ParameterSetName -eq 's2') {
    $UserName = $Credential.UserName
    $PasswordSecured = $Credential.Password
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecured))
}
Write-Verbose "Using username: $($Username)"
$WebRequestParams.Add('Body',@{UserName=$UserName;Password=$Password})
$InitialResponse=Invoke-WebRequest @WebRequestParams -Credential $Credential
$SAMLResponseEncoded=$InitialResponse.InputFields.FindByName('SAMLResponse').value

if (!$SAMLResponseEncoded) {
    Write-Verbose "No valid ADFS assertion received, please try again..."
    Write-Verbose "Suggestion: Either Mistyped password or supply alternate credentials."
    if (!$VerbosePreference) { Write-Warning "Refresh failed, Use -Verbose parameter for more infomration" }
    exit
}

[xml]$SAMLResponse = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($SAMLResponseEncoded))

$AwsRoles=@()
foreach ($att in $SAMLResponse.Response.Assertion.AttributeStatement.Attribute) {
    switch ($att.Name) {
        'https://aws.amazon.com/SAML/Attributes/RoleSessionName' { $RoleSessionName = $att.AttributeValue }
        'https://aws.amazon.com/SAML/Attributes/SessionDuration' { $SessionDuration = $att.AttributeValue }
        'https://aws.amazon.com/SAML/Attributes/Role' { [string[]]$AwsRoles=$att.AttributeValue }
    }
}

if ([string]::IsNullOrEmpty($AwsRoles) -or ($AwsRoles.Count -le 0)) {
    Write-Verbose "No roles to assume has been returned, please try again..."
    Write-Verbose "Suggestion: Either Mistyped password or supply alternate credentials."
    if (!$VerbosePreference) { Write-Warning "Refresh failed, Use -Verbose parameter for more infomration" }
    exit
}

$SelectedRoleIndex="0"
$RoleSelected = $false
if (![string]::IsNullOrEmpty($RoleArn)) {
    Write-Verbose "Looking for role [$RoleArn] in SAML response..."
    $ndx = (0..($AwsRoles.Count-1)) | where {$AwsRoles[$_] -like "*$RoleArn"}
    if ([string]::IsNullOrEmpty($ndx)) {
        Write-Verbose "...not found"
    } else {
        Write-Verbose "...role found"
        $SelectedRoleIndex=[string]$ndx
        $RoleSelected = $true
    }
}

if ((-not $RoleSelected) -and ($AwsRoles.Count -gt 1)) {
    Write-Output "Available roles you could assume:"
    for ($i = 0; $i -lt $AwsRoles.Count; $i++) {
        Write-Output ("[{0}] - {1}" -f $i, $AwsRoles[$i].split(',')[1])
    }
    $SelectedRoleIndex = (Read-Host -Prompt 'Selection')
    if (-not (($SelectedRoleIndex -match "^[\d\.]+$") -and ([int]$SelectedRoleIndex -in 0..$($AwsRoles.Count-1)))) {
        Write-Verbose "You selected an invalid role index, please try again..."
        if (!$VerbosePreference) { Write-Warning "Refresh failed, Use -Verbose parameter for more infomration" }
        exit
    }
}
$RoleArn = $AwsRoles[[int]$SelectedRoleIndex].split(',')[1]
$PrincipalRole = $AwsRoles[[int]$SelectedRoleIndex].split(',')[0]
Write-Verbose "Assuming role [$RoleArn]..."

try {
    $AssumedRole = Use-STSRoleWithSAML -SAMLAssertion $SAMLResponseEncoded -PrincipalArn $PrincipalRole -RoleArn $RoleArn -DurationInSeconds 28800
    #$CliResult = (&aws sts assume-role-with-saml --role-arn $RoleArn --principal-arn $PrincipalRole --saml-assertion $SAMLResponseEncoded --duration-seconds 28800) | Out-String
    #$AssumedRole = ConvertFrom-Json -InputObject $CliResult
} catch {
    Write-Verbose "Unable to assume role [$RoleArn]..."
    Write-Verbose $_
    $AssumedRole = $null
    Write-Verbose "Token refresh failed, please try again..."
    if (!$VerbosePreference) { Write-Warning "Refresh failed, Use -Verbose parameter for more infomration" }
}

if (![string]::IsNullOrEmpty($AssumedRole)) {
    if ($SetSharedCred) {
        Write-Verbose "Storing assumed credential to [$ProfileLocation] as profile [$ProfileName]..."
        Set-AWSCredential -AccessKey $aws_AccessKeyId -SecretKey $aws_SecretAccessKey -SessionToken $aws_SessionToken -StoreAs $ProfileName -ProfileLocation $ProfileLocation
    }
    if ($SetEnvVar) {
        Write-Verbose  "Storing assumed credential to User Environment Variables [AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN]..."
        [System.Environment]::SetEnvironmentVariable('AWS_ACCESS_KEY_ID',$AssumedRole.Credentials.AccessKeyId,[System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable('AWS_SECRET_ACCESS_KEY',$AssumedRole.Credentials.SecretAccessKey,[System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable('AWS_SESSION_TOKEN',$AssumedRole.Credentials.SessionToken,[System.EnvironmentVariableTarget]::User)
        Write-Verbose  "Storing assumed credential to CurrentSession Environment Variables [AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN]..."
        $env:AWS_ACCESS_KEY_ID=$AssumedRole.Credentials.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY=$AssumedRole.Credentials.SecretAccessKey
        $env:AWS_SESSION_TOKEN=$AssumedRole.Credentials.SessionToken
    }
    Write-Verbose "Done..."
}
