[CmdletBinding(DefaultParameterSetName='s2')]
[Parameter()]
Param(
    [string]$RoleArn = '',
    [string]$ProfileName = "saml",
    [string]$ProfileLocation = "$($HOME)\.aws\credentials",
    [string]$DefaultRegion = 'eu-west-1',
    [string]$DefaultOutput = 'json',
    [string]$IdpEndpoint = 'https://sts.contoso.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices',
    [int]$SessionDuration = 28800,
    [switch]$Force = $false,
    [switch]$SetEnvVar = $false,
    [switch]$SetSharedCred = $true,
    [switch]$StoreAsDefaultProfile = $False,
    [switch]$CheckAndInstallModules = $False,
    [switch]$AwsCliPreferred = $False,
    [Parameter (ParameterSetName = 's1', Mandatory = $false)][string]$UserName = '',
    [Parameter (ParameterSetName = 's1', Mandatory = $false)][string]$Password = '',
    [Parameter (ParameterSetName = 's2', Mandatory = $false)][System.Management.Automation.PSCredential]$Credential
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
Write-Verbose "Using following paramter values"
Write-Verbose ">> ProfileName: [$ProfileName]"
Write-Verbose ">> ProfileLocation: [$ProfileLocation]"
Write-Verbose ">> Default Region: [$DefaultRegion]"
Write-Verbose ">> Default Output: [$DefaultOutput]"
Write-Verbose ">> IdpEndpoint: [$IdpEndpoint]"
Write-Verbose ">> SessionDuration: [$SessionDuration]"
Write-Verbose ">> Force SAML token refresh: [$Force]"
Write-Verbose ">> Set Enviroment Variables: [$SetEnvVar]"
Write-Verbose ">> Set Shared Credentials: [$SetSharedCred]"
Write-Verbose ">> Store as Default profile: [$StoreAsDefaultProfile]"
Write-Verbose ">> Check and Install modules prerequisite: [$CheckAndInstallModules]"
Write-Verbose ">> AWS Cli preferred: [$AwsCliPreferred]"
if (![string]::IsNullOrEmpty($RoleArn)) {
    Write-Verbose "Pre-Selected role: [$RoleArn]"
}

if ($CheckAndInstallModules) {
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
} else { 
    Write-Verbose -Message "Bypassing Nuget, Powershell and AWSPowershell prerequisite check..." 
}

# check existence of AWSPowershell and AWS Cli
$cli_awsps = $false
$cli_aws = $false
Write-Verbose -Message "Checking AWSPowershell and AWS Cli:"
$ver_awsps = (Get-Module AWSPowershell -ListAvailable -verbose:$false | Sort Version -Descending | Select -First 1).Version.ToString()
if (![string]::IsNullOrEmpty($ver_awsps)) {
    $cli_awsps=$true
    Write-Verbose -Message ">> found AWSPowershell ver: $ver_awsps"
} else { Write-Verbose -Message ">> AWSPowershell not installed..." }
if (Get-Command "aws" -ErrorAction SilentlyContinue){
    $ver_awscli = (&aws --version)
    $cli_aws =$true
    Write-Verbose -Message ">> found AWS Cli ver: $ver_awscli"
} else { Write-Verbose -Message ">> AWS Cli not installed..." }
if (-not($cli_awsps -or $cli_aws)) {
    Write-Verbose -Message "Nor AWS CLi nor AWS Powershell avilable. Exiting..."
    exit 1
}
if ($AwsCliPreferred -and $cli_aws) { $cli_awsps = $false }

if ($cli_awsps) {
    Write-Verbose -Message ">> using AWSPowershell..."
    Write-Verbose -Message "Importing AWSPowershell comandlets..."
    Import-Module AWSPowerShell -Verbose:$false
} else {    Write-Verbose -Message ">> using Aws Cli..."}

if (!$force) {
    try {
        if ($cli_awsps) { Get-S3Bucket -ProfileName $ProfileName | Out-Null }
        elseif ($cli_aws) {
            (&aws s3 ls --profile $profilename 2>&1) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw $LASTEXITCODE }
        }
        Write-Verbose -Message "Valid credential are still available. No need to refresh. Use -Force to force resfresh"
        exit
    }
    catch {
        Write-Verbose -Message "Credentials expired, processing to refresh"
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
$InitialResponse=Invoke-WebRequest @WebRequestParams -Credential $Credential -Verbose:$false
$AuthMethod=$InitialResponse.InputFields.FindByName('AuthMethod').value
$authContext=$InitialResponse.InputFields.FindByName('Context').value
$SAMLResponseEncoded=$InitialResponse.InputFields.FindByName('SAMLResponse').value
#Write-Verbose $InitialResponse
if (![string]::IsNullOrEmpty($AuthMethod) -and ($AuthMethod -eq 'AzureMfaServerAuthentication')){
    Write-Verbose "Authentication: $AuthMethod"
    Write-Verbose "MFA authorization required..."
}

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
        'https://aws.amazon.com/SAML/Attributes/RoleSessionName' { $RoleSessionNameAtt = $att.AttributeValue }
        'https://aws.amazon.com/SAML/Attributes/SessionDuration' { $SessionDurationAtt = $att.AttributeValue }
        'https://aws.amazon.com/SAML/Attributes/Role' { [string[]]$AwsRoles=$att.AttributeValue }
    }
}

Write-Verbose "Returned SAML assertion attributes:"
Write-Verbose "SessionName: $RoleSessionNameAtt"
Write-Verbose "SessionDuration: $SessionDurationAtt"
$SessionDuration = $SessionDurationAtt

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
    $SelectedRoleIndex = (Read-Host -Prompt 'Selection [0]')
    if ([string]::IsNullOrEmpty($SelectedRoleIndex)) { $SelectedRoleIndex = "0"}
    if (-not (($SelectedRoleIndex -match "^[\d\.]+$") -and ([int]$SelectedRoleIndex -in 0..$($AwsRoles.Count-1)))) {
        Write-Verbose "You selected an invalid role index, please try again..."
        if (!$VerbosePreference) { Write-Warning "Refresh failed, Use -Verbose parameter for more infomration" }
        exit
    }
}
$RoleArn = $AwsRoles[[int]$SelectedRoleIndex].split(',')[1]
$PrincipalRole = $AwsRoles[[int]$SelectedRoleIndex].split(',')[0]
Write-Verbose ">> Principal role: [$PrincipalRole]"
Write-Verbose ">> Assuming role [$RoleArn]..."

$stserr = ""
$AssumedRole = $null
if ($SessionDuration -gt 43200) {$SessionDuration=43200} # maximum alowed time 12 hours
if ($cli_awsps) {
    try {
        $AssumedRole = Use-STSRoleWithSAML -SAMLAssertion $SAMLResponseEncoded -PrincipalArn $PrincipalRole -RoleArn $RoleArn -DurationInSeconds $SessionDuration -Verbose:$false -ErrorAction SilentlyContinue -ErrorVariable stserr
    } catch { $stserr=$_ }
    if (![string]::IsNullOrEmpty($stserr)) {
        Write-Verbose -Message ">> downgrading SessionDuration to 28800..."
        try {
            $AssumedRole = Use-STSRoleWithSAML -SAMLAssertion $SAMLResponseEncoded -PrincipalArn $PrincipalRole -RoleArn $RoleArn -DurationInSeconds 28800 -Verbose:$false -ErrorAction SilentlyContinue -ErrorVariable stserr
        } catch { $stserr=$_ }
    }
} elseif ($cli_aws) {
    $AssumedRoleJson = &aws sts assume-role-with-saml --role-arn $RoleArn --principal-arn $PrincipalRole --saml-assertion $SAMLResponseEncoded --duration-seconds $SessionDuration 2>&1
    if ($AssumedRoleJson | ?{$_.gettype().Name -eq "ErrorRecord"}) { 
        Write-Verbose -Message ">> downgrading SessionDuration to 28800..."
        $AssumedRoleJson = &aws sts assume-role-with-saml --role-arn $RoleArn --principal-arn $PrincipalRole --saml-assertion $SAMLResponseEncoded --duration-seconds 28800 2>&1
        if ($AssumedRoleJson | ?{$_.gettype().Name -eq "ErrorRecord"}) { 
            $stserr = $AssumedRoleJson | Out-String
        } else { $AssumedRole = $AssumedRoleJson | ConvertFrom-Json }
    } else { $AssumedRole = $AssumedRoleJson | ConvertFrom-Json }
}
if (![string]::IsNullOrEmpty($stserr)) {
    Write-Verbose "Unable to assume role [$RoleArn]..."
    Write-Verbose -Message $stserr
    $AssumedRole = $null
    Write-Verbose "Token refresh failed, please try again..."
    if (!$VerbosePreference) { Write-Warning "Refresh failed, Use -Verbose parameter for more infomration" }
}

if (![string]::IsNullOrEmpty($AssumedRole)) {
    Write-Verbose -Message ">> ...success"
    if ($SetSharedCred) {
        Write-Verbose "Storing assumed credential to [$ProfileLocation] as profile [$ProfileName]..."
        if ($cli_awsps) {
            Set-AWSCredential -AccessKey $AssumedRole.Credentials.AccessKeyId -SecretKey $AssumedRole.Credentials.SecretAccessKey -SessionToken $AssumedRole.Credentials.SessionToken -StoreAs $ProfileName -ProfileLocation $ProfileLocation -Verbose:$false
        } elseif ($cli_aws) {
            &aws configure set region $DefaultRegion --profile $ProfileName
            &aws configure set output $DefaultOutput --profile $ProfileName
            &aws configure set aws_access_key_id $AssumedRole.Credentials.AccessKeyId --profile $ProfileName
            &aws configure set aws_secret_access_key $AssumedRole.Credentials.SecretAccessKey --profile $ProfileName
            &aws configure set aws_session_token $AssumedRole.Credentials.SessionToken --profile $ProfileName
        }
        if ($StoreAsDefaultProfile) {
            Write-Verbose "Storing assumed credential to [$ProfileLocation] as Default profile..."
            if ($cli_awsps) {
                Set-AWSCredential -AccessKey $AssumedRole.Credentials.AccessKeyId -SecretKey $AssumedRole.Credentials.SecretAccessKey -SessionToken $AssumedRole.Credentials.SessionToken -StoreAs 'default' -ProfileLocation $ProfileLocation
            } elseif ($cli_aws) {
                &aws configure set region $DefaultRegion 
                &aws configure set output $DefaultOutput 
                &aws configure set aws_access_key_id $AssumedRole.Credentials.AccessKeyId 
                &aws configure set aws_secret_access_key $AssumedRole.Credentials.SecretAccessKey 
                &aws configure set aws_session_token $AssumedRole.Credentials.SessionToken 
            }
        }
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
    } else {
        Write-Verbose  "Removing User Environment Variables [AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN]..."
        [System.Environment]::SetEnvironmentVariable('AWS_ACCESS_KEY_ID',$null,[System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable('AWS_SECRET_ACCESS_KEY',$null,[System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable('AWS_SESSION_TOKEN',$null,[System.EnvironmentVariableTarget]::User)
        Write-Verbose  "Removing CurrentSession Environment Variables [AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN]..."
        $env:AWS_ACCESS_KEY_ID=$null
        $env:AWS_SECRET_ACCESS_KEY=$null
        $env:AWS_SESSION_TOKEN=$null
    }
    Write-Verbose "Done..."
}
