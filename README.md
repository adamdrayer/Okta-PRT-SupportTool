"# Okta-PRT-SupportTool" 

This tool is intended to be used by Okta support to diagnose issues receiving PRTs from Azure AD on Hybrid-Joined or AzureAD-Joined Windows 10/11 devices when the user logging in has a domain suffix that has been federated with Okta.

There are 3 things it looks at:
1. Local Device
2. Azure AD Configurations
3. Okta Tenant Config

This tool makes no changes to any device or environment.  It only gathers information.

SETTING THE OKTA API TOKEN
The Okta API token is necessary to give the tool access to your Okta environment.  Instructions for generating this token can be found at: https://developer.okta.com/docs/guides/create-an-api-token/main/

Once a token has been generated, it can be set for the tool in several ways:
1. Run $global:OktaAPIToken = "<token>"
2. Open SetOktaAPIToken.ps1 and put the token on Line 1.
3. Enter the token manually when executing the script.
  
The tool will attempt to locate the Okta API token by these methods in order:
  1. Check for a pre-existing global variable - This will exist if the tool was recently run from the same Powershell window
  2. Check for the presence of SetOktaAPIToken.ps1, ask if you would like to run the script to set the token
  3. If you choose not to run SetOktaAPIToken.ps1, or if the file is not found, you will be prompted to enter the token manually

IMPORTANT:  Remember to deactivate your token when you are finished, or delete it from any file you have placed it in.  Anyone who has this token has admin access to your Okta tenant.  This tool does not write the token anywhere and so it will only exist in the files where you have placed it.  
  
 AUTHENTICATION TO AZURE AD
This tool uses the Graph API (instead of powershell modules) to access your Azure AD environment.  A pop-up window will launch asking for a code.  You can press ctrl-V / command-V to paste the code from the clipboard into the pop-up window.  Then you will be asked for Azure credentials.  You need to specify an account that has rights to read domain federation settings in Azure.  A global administrator is preferred.  If you use an account that is federated with Okta, the MS login will redirect you to an Okta login to complete the Azure authentication
  

This tool is currently v0.8 as of January 2023.
  
If you have any questions or comments, please contact:
Adam Drayer
Sr. Solutions Engineer
Okta, Inc.
adam.drayer@okta.com
