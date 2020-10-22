Powershell script to extract ADFS SAML token from IDP response

# Get-AwsSaml.ps1

---


## SYNOPSIS
Update AWS session token and store it to shared credential file or environment variables for use with Commandlets, CLI or Terraform

## SYNTAX
``` powershell

    Get-AwsSaml [-RoleArn <string>] [-ProfileName <string>] [-ProfileLocation <string>]
                [-IdpEndpoint <string>] [-SetEnvVar] [-SetSharedCred]
                [ [UserName <string>] [Password <string>] | [Credentials <PSCredential>] | [-Sso] ] [-Verbose]

```


### PARAMETERS

* #### RoleArn
    * Specify specific role to assume automatically. If not provided script will select first returned role. If multiple roles are returned, then selection prompt is displayed

* #### ProfileName
    * Profile Name used to store AWS session credentials into shared credential file. Default value ___'saml'___

* #### ProfileLocation
    * Location of shared credential file. Default value ___'$HOME\\.aws\credentials'___

* #### IdpEndpoint
    * URI for ADFS endpoint. Default value ___'https://sts.contoso.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'___

* #### SetEnvVar
    * Store AWS session credentials in User and Session Environment Variables. Default value ___'false'___

* #### SetSharedCred
    * Store AWS session credentials in shared credential file. Default value ___'true'___

* #### Sso
    * use single sign-on

* #### UserName
    * Username to use to logon. If not provided current session username retrived.

* #### Password
    * Plain text password. If not provided script will prompt for password.

* #### Credential
    * Instead of plain text Username and Password, pass through PSCredential object

## Source:
AWS documentation: https://docs.aws.amazon.com/powershell/latest/userguide/saml-pst.html
