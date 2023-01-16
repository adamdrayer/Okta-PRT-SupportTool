<#
 
.SYNOPSIS
    Okta-PRT-SupportTool v0.8 - by Adam Drayer, January 2023.  Originally modified from DSRegTool V3.7 by Mohammad Zmaili under fair use

.DESCRIPTION
    OKta PRT Support Tool is a PowerShell sciprt to used to troubleshoot issues with Hybrid-Joined Windows 10/11 Devices not getting Primary Refresh Tokens when Azure is Federated with Okta.

.AUTHOR:
    Adam Drayer

.EXAMPLE
    .\Okta-PRT-SupportTool.ps1

#>

Function LogWrite {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [String] $Level = "INFO",

        [Parameter(Position=0,Mandatory=$False)]
        [string] $Message,

        [Parameter(Mandatory=$False)]
        [string] $FGColor,

        [Parameter(Mandatory=$False)]
        [string] $logfile = "OktaPRTSupportTool.log",

        [Parameter(Mandatory=$False)]
        [string] $NoNewLine = $false
    )

    <#
    if ($global:LogToFile) {
        if ($Message -eq " ") {
            Add-Content $logfile -Value " " -ErrorAction SilentlyContinue
        } else {
            $Date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
            Add-Content $logfile -Value "[$date] [$Level] $Message" -ErrorAction SilentlyContinue
        }
    }
    #>

    if ($Message -eq "") {
        $Message = " "
    }

    if ($global:LogToFile) {
        $Date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
        Add-Content $logfile -Value "[$date] [$Level] $Message" -ErrorAction SilentlyContinue
    }

    if ($FGColor -ne "") {
        if ($NoNewLine -eq $true) {
            Write-Host $Message -ForegroundColor $FGColor -NoNewLine
        } else {
            Write-Host $Message -ForegroundColor $FGColor
        }

    } else {
        if ($NoNewLine -eq $true) {
            Write-Host $Message -NoNewLine
        } else {
            Write-Host $Message
        }
    }
}

Function Write-Log{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [String] $Level = "INFO",

        [Parameter(Mandatory=$True)]
        [string] $Message,

        [Parameter(Mandatory=$False)]
        [string] $logfile = "OktaPRTSupportTool.log"
    )
    if ($Message -eq " "){
        Add-Content $logfile -Value " " -ErrorAction SilentlyContinue
    }else{
        $Date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
        Add-Content $logfile -Value "[$date] [$Level] $Message" -ErrorAction SilentlyContinue
    }
}

Function PSasAdmin{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function GetDSRegCmdPRT {
    $AzurePrt = $global:DSRegStatus | Select-String "AzureAdPrt "
    $AzurePrt = ($AzurePrt.tostring() -split ":")[1].trim()
    if ($AzurePrt -eq "YES"){
        $global:AzurePrt = $true
        $AzurePrtUpdateTime = $global:DSRegStatus | Select-String AzureAdPrtUpdateTime
        $AzurePrtUpdateTime_Separator = $AzurePrtUpdateTime.tostring().IndexOf(':') + 1 
        $AzurePrtUpdateTime = $AzurePrtUpdateTime.tostring().substring($AzurePrtUpdateTime_Separator,$AzurePrtUpdateTime.tostring().length-$AzurePrtUpdateTime_Separator).trim()
        #$AzurePrtUpdateTime = ($AzurePrtUpdateTime.tostring() -split ":")[1].trim()
        $AzurePrtUpdateTime = ($AzurePrtUpdateTime.tostring() -split "\.")[0].trim() + "-00:00"
        $global:AzurePrtUpdateDateTime = [DateTime]$AzurePrtUpdateTime
    } else {
        $global:AzurePrt = $false
    }
$GetDSRegCmdPRT = $global:AzurePrt
return $GetDSRegCmdPRT 
}

function Connect-AzureDevicelogin {
    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 1
        #$Timeout = 300
    )
try {
    $DeviceCodeRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
        Body   = @{
            resource  = $Resource
            client_id = $ClientId
            redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
    }
    $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
 
    # Copy device code to clipboard
    $DeviceCode = ($DeviceCodeRequest.message -split "code " | Select-Object -Last 1) -split " to authenticate."
    Set-Clipboard -Value $DeviceCode

    Write-Host ''
    Write-Host "Device code " -ForegroundColor Yellow -NoNewline
    Write-Host $DeviceCode -ForegroundColor Green -NoNewline
    Write-Host "has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the sign in, and close the window to proceed." -ForegroundColor Yellow
    Write-Host "Note: If 'Microsoft Graph Authentication' window didn't open,"($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1) -ForegroundColor gray
    $msg= "Device code $DeviceCode has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the signin, and close the window to proceed.`n                                 Note: If 'Microsoft Graph Authentication' window didn't open,"+($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1)
    Write-Log -Message $msg

    # Open Authentication form window
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
    $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 440; Height = 600; Url = "https://www.microsoft.com/devicelogin" }
    $web.Add_DocumentCompleted($DocComp)
    $web.DocumentText
    $form.Controls.Add($web)
    $form.Add_Shown({ $form.Activate() })
    $web.ScriptErrorsSuppressed = $true
    $form.AutoScaleMode = 'Dpi'
    $form.text = "Microsoft Graph Authentication"
    $form.ShowIcon = $False
    $form.AutoSizeMode = 'GrowAndShrink'
    $Form.StartPosition = 'CenterScreen'
    $form.ShowDialog() | Out-Null
        
    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        Body   = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            code       = $DeviceCodeRequest.device_code
            client_id  = $ClientId
        }
    }
    $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
        if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
            throw 'Login timed out, please try again.'
        }
        $TokenRequest = try {
            Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
        }
        catch {
            $Message = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($Message.error -ne "authorization_pending") {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
    Write-Output $TokenRequest.access_token
}
finally {
    try {
        Remove-Item -Path $TempPage.FullName -Force -ErrorAction Stop
        $TimeoutTimer.Stop()
    }
    catch {
        #Ignore errors here
    }
}
}

Function ConnecttoAzureAD{
    LogWrite ""
    LogWrite "Checking if there is an existing valid Azure AD Access Token for this Powershell session..." -FGColor Yellow
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if($GraphResult.value.Count)
    {
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            LogWrite "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -FgColor Green
            LogWrite ""
    }else {
        LogWrite "There no valid Azure AD Access Token for this powershell session." -FgColor Magenta
        LogWrite "" 
        LogWrite "In order to check all PRT settings, this script needs access to Azure AD.  If you continue, we will copy a code to the clipboard.  When you see the pop-up window, just press Ctrl-V to paste the code.  You will then be prompted for credentials.  Please supply global administrator credentials so that we can query all necessary information" -FGColor Yellow
        LogWrite ""
        Do {
            $Continue = Read-Host -Prompt "Would you like to continue with the Azure AD login? (Y/n): "
        } Until (($Continue -ieq "N") -or ($Continue -ieq "Y"))

        if ($Continue -ieq "Y") {
            LogWrite "Attempting Authentication to Azure" -FGColor Yellow
            $global:accesstoken = Connect-AzureDevicelogin
            LogWrite ""
            if ($global:accesstoken.Length -ge 1) {
                $headers = @{ 
                    'Content-Type'  = "application\json"
                    'Authorization' = "Bearer $global:accesstoken"
                }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            LogWrite "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -FGColor Green
            }
        } else {
        LogWrite "Azure AD Authentcation skipped!  Will not be able to check Azure AD settings" -FGColor Red
        }
    }
}

Function CheckDeviceHealth($DID, $skipPendingCheck){
    #ConnecttoAzureAD
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }

    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$DID'"
    try{
        $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
    }catch{
        Write-Host ''
        Write-Host "Operation aborted. Unable to connect to Azure AD, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
        Write-Host ''
    }

    if ($GraphResult) {
        $AADDevice=$GraphResult.Content | ConvertFrom-Json
        if($AADDevice.value.Count -ge 1){
            #Device returned
            $deviceExists=$true
            $deviceEnabled = $AADDevice.value.accountEnabled
            $LastLogonTimestamp=$AADDevice.value.approximateLastSignInDateTime
            $trusttype = $AADDevice.value.trusttype
    
            $Cert=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($AADDevice.value.alternativeSecurityIds.key))
            $AltSec = $Cert -replace $cert[1]
    
            if (-not ($AltSec.StartsWith("X509:"))){
                $devicePending=$true
            }else{
                $devicePending=$false
            }
    
        }else{
            #Device does not exist
            $deviceExists=$false
        }
        LogWrite "Testing device status on Azure AD..." -FgColor Yellow
        LogWrite ""
    
        #Check if the device exist:
        LogWrite "Testing if device exists on Azure AD..." -FGColor Yellow
        if ($deviceExists){
            #The device existing in AAD:
            LogWrite "Test passed: the device object exists on Azure AD" -FGColor Green
            LogWrite ""
        }else{
            #Device does not exist:
            LogWrite "Test failed: the device does not exist in your Azure AD tenant" -FGColor Red
            LogWrite ""
        }
    
        #Check if the device is enabled:
        ''
        LogWrite "Testing if device is enabled on Azure AD..." -FGColor Yellow
        if ($deviceEnabled){
            LogWrite "Test passed: the device is enabled on Azure AD tenant" -FGColor Green
            LogWrite ""
        }else{
            LogWrite "Test failed: the device is not enabled on Azure AD tenant" -FGColor Red
            LogWrite ""
        }
    
        if(($trusttype)){
            #Check if the device is Hybrid
            LogWrite "Testing device Join state..." -FGColor Yellow
            if ($trusttype -ieq 'ServerAd'){
                LogWrite "The device is reporting as Hybrid Joined. (TrustType = $trusttype)" -FGColor Green
                LogWrite ""
            } elseif ($trusttype -ieq 'AzureAD') {
                    LogWrite "The device is reporting as AAD-Joined Only (TrustType = $trusttype)" -FGColor Green
                    LogWrite ""
            } else {
                LogWrite "The device is reporting as Registered Only - or Unknown (TrustType = $trusttype)" -FGColor Red
                LogWrite ""
            }
        }
        if(!($skipPendingCheck)){
            #Check if the device is registered (not Pending):
            LogWrite "Testing device PENDING state..." -FGColor Yellow
            if ($devicePending){
                LogWrite "Test failed: the device in 'Pending' state on Azure AD." -FGColor Red
                LogWrite ""
            } else {
                    LogWrite "Test passed: the device is not in PENDING state" -FGColor Green
                    LogWrite ""
            }
        }
    
        LogWrite "Checking if device is stale..." -FGColor Yellow
        $CurrentDate = Get-Date 
        $Diff = New-TimeSpan -Start $LastLogonTimestamp -End $CurrentDate
        $diffDays=$Diff.Days
        if(($diffDays -ge 21) -or ($diffDays.length -eq 0)){
            LogWrite "Device could be stale" -FGColor Yellow
            LogWrite ""
        }else{
        LogWrite "Device is not stale" -FGColor Green
        LogWrite ""
    }
        if($diffDays.length -eq 0) {
            Write-Host "There is no sign in yet on this device" -ForegroundColor Yellow
            Write-Log -Message "There is no sign in yet on this device" -Level WARN
        }else{
            LogWrite "Last logon timestamp: $LastLogonTimestamp UTC, $diffDays days ago" -FGColor Green
            LogWrite ""
        }
    } else {
        LogWrite "Unable to retrieve Device settings from Azure!" -FGColor Red
        LogWrite ""
    }
Return $AADDevice.value
 
}

Function InitLogging {
    Add-Content ".\OktaPRTSupportTool.log" -Value "." -ErrorAction SilentlyContinue
    Write-Host ''
    if($Error[0].Exception.Message -ne $null){
        if($Error[0].Exception.Message.Contains('denied')){
            Write-Host "Was not able to create log file.  No log file will be generated" -ForegroundColor Red
            Write-Host ''
            $global:LogToFile = $false
        }else{
            Write-Host "OktaPRTSupportTool.log file has been created." -ForegroundColor Yellow
            Write-Host ''
        }
    }else{
        Write-Host "OktaPRTSupportTool.log file is writable." -ForegroundColor Yellow
        Write-Host ''
    }
}

Function SetGlobalVariables {
    $global:LogToFile = $true
    $global:DomainAuthType=""
    $global:MEXURL=""
    $global:MEXURLRun=$true
    $global:DCTestPerformed=$false
    $global:Bypass=""
    $global:login=$false
    $global:device=$false
    $global:enterprise=$false
    $global:ProxyServer=""
    $global:ToolVer = "v0.8"
    $global:DeviceName = (Get-Childitem env:computername).value
    $global:OSVersion = ([environment]::OSVersion.Version).major
    $global:OSBuild = ([environment]::OSVersion.Version).Build
    $global:OSVer = (([environment]::OSVersion).Version).ToString()
    $global:OSEdition = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    $whoami=whoami
    $whoami=$whoami.split("\")
    if ($whoami[1].Length -gt 0) {
        $global:samAccountName = $whoami[1]
    } else {
        $global:samAccountName = $whoami[0]
    }    
    $global:UserUPN=whoami /upn
    $global:IsDomainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    $global:DomainName = $env:USERDNSDOMAIN
    $global:DSRegStatus = dsregcmd /status    
    $CurrentSession = quser $env:username
    $CurrentSession = $CurrentSession | ForEach-Object -Process {$_ -replace '\s{2,}',',' }
    $CurrentSession = $CurrentSession | ConvertFrom-Csv
    $CurrentSessionLogonTime = [datetime]$CurrentSession.'LOGON TIME'
    #$CurrentSessionLogonTime = $CurrentSessionLogonTime.AddMinutes(-(([TimeZoneInfo]::Local).BaseUtcOffset.TotalMinutes)) #Convert to UTC
    $global:CurrentLogonTime = $CurrentSessionLogonTime

}

Function GetDSRegCmd_AADJoin {
        #Check for AAD-Joined
        $AADJ = $global:DSRegStatus | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            $global:DSRegCmd_AADJ = $true
        } else {
            $global:DSRegCmd_AADJ = $false
        }
    return $global:DSRegCmd_AADJ
}

Function GetDSRegCmd_AADReg {
    #Check for Workplace-Joined (aka AAD-Registered)
    $WPJ = $global:DSRegStatus | Select-String WorkplaceJoined | Select-Object -First 1
    $WPJ = ($WPJ.tostring() -split ":")[1].trim()
    if ($WPJ -eq 'YES'){
        $global:DSRegCmd_WPJ = $true
    } else {
        $global:DSRegCmd_WPJ = $false
    }
    return $global:DSRegCmd_WPJ

}

Function GetDSRegCmd_JoinType {

    $JoinStatus = ([int]$global:IsDomainJoined).tostring() + ([int]$global:DSRegCmd_AADJ).tostring() + ([int]$global:DSRegCmd_WPJ).tostring()
    #LogWrite "$global:IsDomainJoined, $global:DSRegCmd_AADJ, $global:DSRegCmd_WPJ"
    #LogWrite $JoinStatus

    switch ($JoinStatus) 
    {
        "000" {$DSRegCmd_JoinType = "Not Joined or Registered"}
        "001" {$DSRegCmd_JoinType = "AzureAD-Registered Only"}
        "010" {$DSRegCmd_JoinType = "AzureAD-Joined Only"}
        "011" {$DSRegCmd_JoinType = "AzureAD-Joined + AzureAD-Registered"}
        "100" {$DSRegCmd_JoinType = "Domain-Joined Only"}
        "101" {$DSRegCmd_JoinType = "Domain-Joined + Azure AD Registered"}
        "110" {$DSRegCmd_JoinType = "Hybrid (Domain-Joined + AzureAD-Joined)"}
        "111" {$DSRegCmd_JoinType = "Hybrid (Domain-Joined + AzureAD-Joined + AzureAD-Registered)"}
        default {$DSRegCmd_JoinType = "unknown"}
    }

    #LogWrite "$DSRegCmd_JoinType"
    return $DSRegCmd_JoinType
}

Function GetDSRegCmd_TenantId {
    $DSReg_TenantId = $global:DSRegStatus | Select-String TenantId | Select-Object -First 1
    $DSReg_TenantId = ($DSReg_TenantId.tostring() -split ":")[1].trim()
    if ($DSReg_TenantId){
        $global:DSRegCmd_TenantId = $DSReg_TenantId
    } else {
        $global:DSRegCmd_TenantId = ''
    }
    return $DSReg_TenantId

}

Function GetDSRegCmd_TenantName {
    $DSReg_TenantName = $global:DSRegStatus | Select-String TenantName | Select-Object -First 1
    $DSReg_TenantName = ($DSReg_TenantName.tostring() -split ":")[1].trim()
    if ($DSReg_TenantName){
        $global:DSRegCmd_TenantName = $DSReg_TenantName
    } else {
        $global:DSRegCmd_TenantName = ''
    }
    return $DSReg_TenantName

}

Function GetDSRegCmd_DeviceId {
    $DSReg_DeviceId = $global:DSRegStatus | Select-String DeviceId | Select-Object -First 1
    $DSReg_DeviceId = ($DSReg_DeviceId.tostring() -split ":")[1].trim()
    return $DSReg_DeviceId
}

Function TestAzureConnection {
    $statuscode = (Invoke-WebRequest -Uri https://adminwebservice.microsoftonline.com/ProvisioningService.svc -UseBasicParsing).statuscode
    if ($statuscode -eq 200) {
        $global:InternetConnected = $true
    } else {
        $global:InternetConnected = $false
    }
}

Function GetAzureFederationInfo {
    $upn = $global:UserUPN
    LogWrite "Attempting to query Azure AD Federation settings for user: $upn" -FGColor Yellow
    $UserRealmUrl = "https://login.microsoftonline.com/common/UserRealm/?user=$upn&api-version=1.0"
    $UserRealmJson = Invoke-WebRequest -uri $UserRealmUrl -UseBasicParsing

 
    If ($UserRealmJson) {
        LogWrite "Azure AD Federation Settings found for current user $upn" -FGColor Green
        LogWrite ""
        $UserRealm = $UserRealmJson | ConvertFrom-Json
        $account_type = $UserRealm.account_type
        $domain_name = $UserRealm.domain_name
        $federation_protocol = $UserRealm.federation_protocol
        $federation_metadata_url = $UserRealm.federation_metadata_url
        $federation_active_auth_url = $UserRealm.federation_active_auth_url
        LogWrite "Account Type              : $account_type" -FGColor Yellow
        LogWrite "Domain Name               : $domain_name" -FGColor Yellow
        LogWrite "Federation Protocol       : $federation_protocol" -FGColor Yellow
        LogWrite "Federation Metadata URL   : $federation_metadata_url" -FGColor Yellow
        LogWrite "Federation Active Auth URL: $federation_active_auth_url" -FGColor Yellow
        LogWrite ""
    } else {
        LogWrite "Unable to query Azure AD Federation Settings for current user $upn"
        LogWrite ""
    }
    Return $UserRealm
}

Function GetAzureUserInfo {
    $upn = $global:UserUPN
    LogWrite "Attempting to query Azure AD Federation settings for user: $upn" -FGColor Yellow
    $headers = @{ 
        'Content-Type'  = "application\json"
        'Authorization' = "Bearer $global:accesstoken"
        }

    $AzureUserInfoUrl = "https://graph.microsoft.com/v1.0/users/$upn" + '?$select=id,userPrincipalName,displayName,accountEnabled,onPremisesImmutableId'
    
    try {
        $AzureUserInfoJson = Invoke-WebRequest -uri $AzureUserInfoUrl -Headers $headers -UseBasicParsing -Method "GET" -ContentType "application/json"
    } catch {
        LogWrite "$Error[0]"
    }

    if ($AzureUserInfoJson) {
        LogWrite "Azure AD User Info found for current user $upn" -FGColor Green
        LogWrite ""        
        $AzureUserInfo = $AzureUserInfoJson.content | ConvertFrom-Json                
        LogWrite "User Object ID    : $($AzureUserInfo.id)" -FGColor Yellow
        LogWrite "UserPrincipalName : $($AzureUserInfo.userPrincipalName)" -FGColor Yellow
        LogWrite "DisplayName       : $($AzureUserInfo.displayName)" -FGColor Yellow
        LogWrite "Account Enabled   : $($AzureUserInfo.accountEnabled)" -FGColor Yellow
        LogWrite "ImmutableId       : $($AzureUserInfo.onPremisesImmutableId)" -FGColor Yellow
        LogWrite ""
    } else {
        LogWrite "Unable to find Azure AD user info for current user $upn" -FGColor Red
        LogWrite ""
        $AzureUserInfo = $null
    }
    Return $AzureUserInfo
}

Function GetOffice365App_byDomain {
    Param ([string] $Domain)
    #Get All Okta Office 365 Apps
    $OktaO365AppsUrl = "$global:OktaTenantUrl/api/v1/apps?filter=name+eq+%22office365%22"

    try {
        $OktaO365AppsJson = Invoke-WebRequest -uri $OktaO365AppsUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
        $OktaO365Apps = $OktaO365AppsJson.Content | ConvertFrom-Json
    } catch {
        LogWrite "$Error[0]"
    }

    #Get Office 365 App for User
    $OktaOffice365InstanceId = $Null

    if ($OktaO365Apps.count -gt 0) {
        #Check for Active
        $OktaO365Apps_Active = $OktaO365Apps | Where-Object {$_.status -match "ACTIVE"}
        $OktaO365Apps_Active.settings.app.domains | Foreach {
            if (($_.name -match $Domain) -And ($OktaOffice365InstanceId -eq $null)) {
                $OktaOffice365InstanceId = $_.InstanceId
            }
        }
        if ($OktaOffice365InstanceId -eq $null) {
            #No Active app, Check All Apps
            LogWrite "No Active Office365 App Found for domain: $Domain" -FGColor Red
            $OktaO365Apps = $OktaO365Apps | Where-Object {$_.status -match "ACTIVE"}
            $OktaO365Apps.settings.app.domains | Foreach {
                if (($_.name -match $Domain) -And ($OktaOffice365InstanceId -eq $null)) {
                    $OktaOffice365InstanceId = $_.InstanceId
                }
            }
        }    
    } else {
        LogWrite "NO OFFICE 365 APPS FOUND!" -FGColor Red
        LogWrite ""
    }

<#    If ($OktaOffice365InstanceId -eq $null) {
        LogWrite "Unable to determine Okta Office 365 Instance Id" -FGColor Red
        $UserInputOffice365Id = Read-Host -Prompt "Please enter the Instance Id of the Office 365 App for this user (i.e., exk2q6pxxxxxxlRDs697): "
        $OktaOffice365InstanceId = $UserInputOffice365Id

        $OktaO365AppsUrl = "$OktaTenantUrl/api/v1/apps/$OktaOffice365InstanceId"
        try {
            $OktaO365AppsJson = Invoke-WebRequest -uri $OktaO365AppsUrl -Headers $global:$OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
            $OktaO365Apps = $OktaO365AppsJson.Content | ConvertFrom-Json
        } catch {
            LogWrite "$Error[0]"
            $OktaOffice365InstanceId = $Null
        }
        LogWrite ""
    } else {
        LogWrite "Office 365 Instance Found in Okta!  InstanceId is: $OktaOffice365InstanceId" -FGColor Green
        LogWrite ""
    }
#>

    If ($OktaOffice365InstanceId -ne $null) {
        $OktaO365AppsUrl = "$global:OktaTenantUrl/api/v1/apps/$OktaOffice365InstanceId"
        try {
            $OktaO365AppsJson = Invoke-WebRequest -uri $OktaO365AppsUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
            $OktaO365App = $OktaO365AppsJson.Content | ConvertFrom-Json
        } catch {
            LogWrite "$Error[0]"
            $OktaOffice365InstanceId = $Null
            $OktaO365App = $null
        }
    } else {
        $OktaO365App = $null
    }

    return $OktaO365App
}

Function GetO365AppUser_byUPN {
    Param ([string]$AppInstanceId, [string]$UserUPN)

    $OktaO365AppUsersAPIUrl = "$global:OktaTenantUrl/api/v1/apps/$AppInstanceId/users"
    $OktaO365AppUsers = @()
    $OktaO365AppUserId = $Null
    
    Do {
        try {
            $OktaO365AppUsersJson = Invoke-WebRequest -uri $OktaO365AppUsersAPIUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
            $OktaO365AppUsers += ($OktaO365AppUsersJson.Content | ConvertFrom-Json)
        } catch {
            LogWrite "$Error[0]"
        }
        $nextPage = $OktaO365AppUsersJson.relationlink.next
        $OktaO365AppUsersAPIUrl = $nextPage
    } Until ($nextPage.length -eq 0)
    
    If ($OktaO365AppUsers.count -gt 0) {
        $OktaO365AppUsers | Foreach {
            if (($_.credentials.userName -match $userUPN) -And ($OktaO365AppUserId -eq $null)) {
                $OktaO365AppUser = $_
            }
        }    
    } else {
        $OktaO365AppUser = $null
    }
    Return $OktaO365AppUser
}

Function GetO365AppUser_samAccountName {
    Param ([string]$AppInstanceId, [string]$samAccountName)

    $OktaO365AppUsersAPIUrl = "$global:OktaTenantUrl/api/v1/apps/$AppInstanceId/users"
    $OktaO365AppUsers = @()
    $OktaO365AppUserId = $Null
    
    Do {
        try {
            $OktaO365AppUsersJson = Invoke-WebRequest -uri $OktaO365AppUsersAPIUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
            $OktaO365AppUsers += ($OktaO365AppUsersJson.Content | ConvertFrom-Json)
        } catch {
            LogWrite "$Error[0]"
        }
        $nextPage = $OktaO365AppUsersJson.relationlink.next
        $OktaO365AppUsersAPIUrl = $nextPage
    } Until ($nextPage.length -eq 0)
    
    If ($OktaO365AppUsers.count -gt 0) {
        $OktaO365AppUsers | Foreach {
            if (($_.credentials.userName -match $global:samAccountName) -And ($OktaO365AppUserId -eq $null)) {
                $OktaO365AppUser = $_
            }
        }    
    } else {
        $OktaO365AppUser = $null
    }
    Return $OktaO365AppUser
}

Function GetOktaUser_ByUPN {
    Param ([string]$UPN)

    $OktaUsersUrl = "$global:OktaTenantUrl/api/v1/users/$UPN"
    $OktaUser = $Null
    
    try {
        $OktaUserJson = Invoke-WebRequest -uri $OktaUsersUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
        $OktaUser = ($OktaUserJson.Content | ConvertFrom-Json)
    } catch {
        LogWrite "$Error[0]"
        $OktaUser = $null
    }
    Return $OktaUser
}

Function GetOktaUserO365App_ByOktaUserId {
    Param ([string]$UserId, [string]$O365InstanceId)

    $OktaUsersUrl = "$global:OktaTenantUrl/api/v1/apps/$O365InstanceId/users/$UserId"
    $OktaUser = $Null
    
    try {
        $OktaUserJson = Invoke-WebRequest -uri $OktaUsersUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
        $OktaUser = ($OktaUserJson.Content | ConvertFrom-Json)
    } catch {
        LogWrite "$Error[0]"
        $OktaUser = $null
    }
    Return $OktaUser

}

Function GetOktaSystemLogPRTEvents {
    Param ( 
        [string]$UserId = ""
    )

    #$UserId = "00u2q6ujzd1it3DG1697"
    $EventType = "policy.evaluate_sign_on"
    $UserAgent = "Windows-AzureAD-Authentication-Provider"

    $Filterstring = "?filter=eventType eq ""$EventType"" and actor.id eq ""$UserId"" and client.userAgent.rawUserAgent sw ""$UserAgent"""

    $OktaLogsUrl = "$global:OktaTenantUrl/api/v1/logs" + $Filterstring
    $OktaLogEvents = $Null
    
    try {
        $OktaLogsJson = Invoke-WebRequest -uri $OktaLogsUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
        $OktaLogEvents = ($OktaLogsJson.Content | ConvertFrom-Json)
    } catch {
        LogWrite "$Error[0]"
        $OktaLogEvents = $null
    }
    Return $OktaLogEvents
}

Function SetOktaAPIToken {

    LogWrite "Checking to see if there is an API Token set..." -FGColor Yellow

    if ($global:OktaAPIToken.Length -gt 1) {
        LogWrite "Okta API Token Found, $(($global:OktaAPIToken+"     ").Substring(0,5))... - Continuing" -FGColor Green
        LogWrite ""
    } else {
        LogWrite "No Okta API Token found.  Checking for 'SetOktaToken.ps1' file..." -FGColor Magenta
        if (Test-Path -Path "./SetOktaToken.ps1") {
            Logwrite "SetOktaToken.ps1 found.  Do you want to run this script to set the token? (Y/n): " -FGColor Yellow -NoNewLine $true
            $RunTokenScript = Read-Host
            if ($RunTokenScript -match "y") {
                . "./SetOktaToken.ps1"
            }
        } else {
            Logwrite "SetOktaToken.ps1 not found" -FGColor Yellow
        }
    }    

#Enter Token Manually if Necessary
    if (!($global:OktaAPIToken.Length -gt 1)) {
        Logwrite "Token Not Set.  Do you want to set the token manually? (Y/n): " -FGColor Yellow -NoNewLine $true
        $SetAPITokenManually = Read-Host
        if ($SetAPITokenManually -match "y") {
            Logwrite "Please enter the API Token: " -FGColor Yellow -NoNewLine $true
            $OktaApiToken = Read-Host
            if ($OKtaApiToken.length -gt 0) {
                $global:OktaAPIToken = $OktaApiToken
            } else {
                Logwrite "Exiting Script.  No Okta API Token detected." -FGColor Red
                Exit
            }
        } else {    
            Logwrite "Exiting Script.  Please set the Okta API Token using the SetOktaToken.ps1 script or enter the token manually next time." -FGColor Red
            Exit
        }
    }
}

Function SetOktaAPIHeaders {
    Param (
        [string]$OktaApiToken = $global:OktaAPIToken
    )

    #Set OktaHeaders
$OktaHeaders = @{ 
    'Content-Type'  = "application/json"
    'Authorization' = "SSWS $OktaApiToken"
    'Accept' = "application/json"
}
$global:OktaHeaders = $OktaHeaders


}

#START MAIN LOOP
#------------------------------------------------------------------------------------------

$ErrorActionPreference= 'silentlycontinue'

Clear-Host

InitLogging

LogWrite "==========================================================="
LogWrite "                   Okta PRT Support Tool                   " -FGColor Green 
LogWrite "==========================================================="
LogWrite "Authored by Adam Drayer, adam.drayer@okta.com" -FGColor Yellow
LogWrite ""
LogWrite "Okta PRT Support Tool $global:ToolVer has started" -FGColor Yellow
LogWrite ""
LogWrite "Setting Global Variables..." -FGColor Yellow
SetGlobalVariables
LogWrite ""

#Check if Powershell running as admin
$IsRunningAsAdmin = PSasAdmin
if ($IsRunningAsAdmin) {
    LogWrite "This script is running in PowerShell as an admin." -FGColor Yellow    
    LogWrite ""
}
LogWrite ""

#Is Windows Version Supported?
if (($global:OSVersion -ge 10) -and ($global:OSBuild -ge 1511)) {
    $OSVerString = $global:OsVer + " (Supported)"    
} else {
    $OSVerString = $global:OsVer + " (Not Supported)"    
}

#Is Windows Edition Supported?
if (!($global:OSEdition -match "Home")) { 
    $OSEditionString = $global:OSEdition + " (Supported)"    
} else {
    $OSEditionString = $global:OSEdition + " (Not Supported)"    
}

#Test for Domain Name
if ($global:DomainName) {
    $DomainNameString = $global:DomainName
} else {
    $DomainNameString = "n/a"
}

#Start Displaying Basic Info
LogWrite "Device Name          : $global:DeviceName"
LogWrite "Windows Version      : $OSVerString"
LogWrite "OS Edition           : $OSEditionString"
LogWrite "User Account         : $global:samAccountName"
LogWrite "User Principal Name  : $global:UserUPN"
LogWrite "Domain Joined?       : $global:IsDomainJoined"
LogWrite "Domain Name          : $DomainNameString"
LogWrite ""

LogWrite "Starting Check of Configuration Settings..." -FGColor Yellow
LogWrite ""

LogWrite "Step 1 of 3 - Checking Local Device Settings..." -FGColor Yellow
LogWrite "===============================================" 
LogWrite ""

LogWrite "Checking for Active PRT..." -FGColor Yellow
$DSRegCmd_PRT = GetDSRegCmdPRT
if ($DSRegCmd_PRT) {
    LogWrite "DSRegCmd is reporting an active PRT!" -FGColor Green
    LogWrite "PRT Timestampe is: $($global:AzurePrtUpdateDateTime.tostring()) UTC" -FGColor Green
    LogWrite "Current Session Logon Time is: $($global:currentlogontime.tostring()) UTC" -FGColor Green
} else {
    LogWrite "DSRegCmd is reporting that PRT has not been issued " -FGColor Red
}
LogWrite ""

LogWrite "Checking for Azure Device Join Status..." -FGColor Yellow
$DSRegCmd_AADJoin = GetDSRegCmd_AADJoin
$DSRegCmd_AADReg = GetDSRegCmd_AADReg
LogWrite "Azure AD Joined?      : $DSRegCmd_AADJoin" -FGColor Green
LogWrite "Azure AD Registered?  : $DSRegCmd_AADReg" -FGColor Green

$DSRegCmd_JoinType = GetDSRegCmd_JoinType
LogWrite "Device is Reporting as: $DSRegCmd_JoinType" -FGColor Green
LogWrite ""

If (($DSRegCmd_AADJoin) -or ($DSRegCmd_AADReg)) {
    LogWrite "Checking for Azure Tenant ID Settings..." -FGColor Yellow
    $DSRegCmd_TenantID = GetDSRegCmd_TenantID
    $DSRegCmd_TenantName = GetDSRegCmd_TenantName
    if ($DSRegCmd_TenantId) {
        LogWrite "TenantId is    : $DSRegCmd_TenantID" -FGColor Green
        LogWrite "TenantName is  : $DSRegCmd_TenantName" -FGColor Green
        LogWrite ""
    } else {
        LogWrite "Tenant Info not found in DSREGCMD /STATUS!" -FGColor Red
        LogWrite ""
    }
} else {
    LogWrite "Device not reporting as joined or registred with an Azure AD Tenant..." -FGColor Red
    LogWrite ""

}

#Getting Device Hybrid Join DateTime
LogWrite "Checking for Azure AD Join Date & Time..." -FGColor Yellow
$UserDeviceRegEvents = Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin"
$UserDeviceRegEvents_AAD = @{}
$UserDeviceRegEvents_AAD = $UserDeviceRegEvents | Where-Object {$_.Id -eq '104'} | Sort-Object TimeCreated -Desc
if ($UserDeviceRegEvents_AAD.count -gt 0) {
    $global:UserDevRegEvent_AAD = $UserDeviceRegEvents_AAD[0]
    $AADDeviceJoinTime = $null     
    $AADDeviceJoinTime = [datetime]$global:UserDevRegEvent_AAD.TimeCreated
    if ($AADDeviceJoinTime -ne $null) {
        LogWrite "Windows Event found for Device Join to Azure AD.  DateTime: $AADDeviceJoinTime" -FGColor Green
        LogWrite ""
    } else {    
        LogWrite "Event exists, but unable to determine the datetime for Device Join to Azure AD" -FGColor Red
        LogWrite ""
    }
} else {
    LogWrite "Windows Event not found for device join to Azure AD" -FGColor Red
    LogWrite ""
$global:UserDevRegEvent_AAD = $null
    $AADDeviceJoinTime = $null         
}

LogWrite ""

LogWrite "Step 2 of 3 - Checking Azure AD Settings..." -FGColor Yellow
LogWrite "===============================================" 
LogWrite ""

Logwrite "Testing Internet Connection to Azure AD" -FGColor Yellow
TestAzureConnection
if ($global:InternetConnected) {
    LogWrite "Azure AD Tenant Reachable - Internet OK" -FGColor Green
} else {
    LogWrite "Azure AD Tenant Unreachable! - Please Check Internet Connection and DNS Settings" -FGColor Red
}

ConnecttoAzureAD

LogWrite "Checking DSREGCMD /STATUS for DeviceId..." -FGColor Yellow
$DSRegCmd_DeviceId = GetDSRegCmd_DeviceId

if ($DSRegCmd_DeviceId) {
    $global:DeviceId = $DSRegCmd_DeviceId
    LogWrite "Device ID: $DSRegCmd_DeviceId" -FGColor Green
} else {
    LogWrite "ERROR - Unable to obtain Device ID from DSREGCMD /STATUS " -FGColor Red
}
LogWrite ""

$AAD_Device = CheckDeviceHealth -DID $DSRegCmd_DeviceId -skipPendingCheck $false
$global:AAD_Device = $AAD_Device

$AzureUserInfo = GetAzureUserInfo 
$global:AzureUserInfo = $AzureUserInfo
$AzureUserDomain = ($AzureUserInfo.UserPrincipalName).split('@')[1]

$AzureFederationInfo = GetAzureFederationInfo
$global:AzureFederationInfo = $AzureFederationInfo

LogWrite "Checking to see if Azure Federation URL is an Okta Tenant..." -FGColor Yellow
$OktaActiveAuthUrl = $null
if ($AzureFederationInfo.federation_active_auth_url -match "okta.com") {
    $OktaActiveAuthUrl = $AzureFederationInfo.federation_active_auth_url
    LogWrite "Azure Federation Partner URL is Okta.com!" -FGColor Green
    LogWrite ""
} else {
    $CheckCName = $null
    try {
        $CheckCName = Resolve-DnsName -Name $AzureFederationInfo.federation_active_auth_url -Type CNAME -DnsOnly
        $p[0].NameHost
    } catch {
        $CheckCName = $null
        $OktaActiveAuthUrl = $null
        LogWrite "Azure Federation Partner URL is not okta.com and has no CNAME record" -FGColor Red
        LogWrite ""
    }
    If ($CheckCName -match "okta.com") {
        $OktaActiveAuthUrl = $CheckCName
        LogWrite "Azure Federation Partner URL is a Custom Domain with a CNAME for okta.com!" -FGColor Green
        LogWrite ""
    } else {
        $OktaActiveAuthUrl = $null
        LogWrite "Azure Federation Partner URL is not okta.com and CNAME record points somewhere else: $CheckCName" -FGColor Red
        LogWrite ""
    }

}

#$federation_metadata_url = $UserRealm.federation_metadata_url
#$federation_active_auth_url = $UserRealm.federation_active_auth_url



LogWrite "Step 3 of 3 - Checking Okta Settings..." -FGColor Yellow
LogWrite "===============================================" 
LogWrite ""

#Set OKta API Token
SetOktaAPIToken

#Get Tenant Info
Logwrite "Determining Okta Tenant Info" -FGColor Yellow

if ($global:AzureFederationInfo.federation_active_auth_url -match "okta.com") {
    $OktaTenantUrl = "https://" + $global:AzureFederationInfo.federation_active_auth_url.Split("/")[2]
    $OktaTenantSubDomain = ($global:AzureFederationInfo.federation_active_auth_url.Split("/")[2]).split(".")[0]
    LogWrite "Okta Base Tenant URL  : $OktaTenantUrl" -FGColor Green
    LogWrite "Okta Tenant Subdomain : $OktaTenantSubDomain " -FGColor Green
    LogWrite ""
} else {
    LogWrite "Unable to determine Okta Tenant URL from Azure AD Settings." -FGColor Red
    $UserInputTenant = Read-Host -Prompt "Please enter the OKTA URL of the tenant -- not custom domain -- (i.e., https://xxxxx.okta.com): "
    $OktaTenantUrl = $UserInputTenant
    $OktaTenantSubDomain = ($OktaTenantUrl.Split("/")[2]).split(".")[0]
    LogWrite ""
}

SetOktaAPIHeaders

$OktaTenantTestUrl = "$OktaTenantUrl/api/v1/users/me"
If ($OktaTenantTestUrl -ne $null) {
    $global:OktaTenantUrl = $OktaTenantUrl
}
$OktaTenantTest = Invoke-WebRequest -uri $OktaTenantTestUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
If ($OktaTenantTest.StatusCode -ne "200") {
    LogWrite "Unable to connect to Okta API Endpoint for tenant $OktaTenantURL with provided API token." -FGColor Red
    LogWrite "Please specify tenant URL (i.e., https://xxx.okta.com): " -NoNewLine $true
    $OktaTenantUrl = Read-Host
    LogWrite "Please input API Token (or press Enter to keep existing -> '$(($global:OktaAPIToken+"     ").Substring(0,5))...'): " -NoNewLine $true
    $NewOktaApiToken = Read-Host
    $OktaTenantUrl = $OktaTenantUrl.TrimEnd("/")
    LogWrite "Tenant set to $OktaTenantUrl"
    if ($NewOktaApiToken.length -gt 0) {
        $global:OktaAPIToken = $NewOktaApiToken
        SetOktaAPIHeaders

        $OktaTenantTest = Invoke-WebRequest -uri $OktaTenantTestUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
        If ($OktaTenantTest.StatusCode -ne "200") {
            Logwrite "Exiting Script.  API Token not valid for given tenant." -FGColor Red
            Exit    
        } else {
            Logwrite "API Token is valid for given tenant $OktaTenantUrl" -FGColor Green
            LogWrite ""
        }

    } else {
        Logwrite "Exiting Script.  API Token not valid for tenant $OktaTenantUrl" -FGColor Red
        Exit
    }
}
    LogWrite ""


#Get Okta Office 365 App
LogWrite "Getting Office 365 App Data for domain: $AzureUserDomain" -FGColor Yellow
$OktaO365App = GetOffice365App_byDomain -Domain $AzureUserDomain

if ($OktaO365App -ne $null) {
    LogWrite "Office 365 Details Retrieved!  App Instance Id: $($OktaO365App.Id)" -FGColor Green
    if ($OktaO365App.Status -match "ACTIVE") {
        LogWrite "Status: $($OktaO365App.Status)" -FGColor Green
    } else {
        LogWrite "Status: $($OktaO365App.Status)" -FGColor Red
    }
    LogWrite ""
} else {
    LogWrite "Error - Unable to find App in Okta for domain: $AzureUserDomain...." -FGColor Red
    LogWrite ""
}

LogWrite "Looking to see if UPN '$global:UserUpn' is assigned to Office 365 App Instance: '$($OktaO365App.Id)'..." -FGColor Yellow
$OktaO365AppUser = GetO365AppUser_byUPN -AppInstanceId $OktaO365App.Id -UserUPN $global:UserUPN

If ($OktaO365AppUser -eq $null) {
    LogWrite "ERROR! - Unable to locate Okta user for Office 365 app!" -FGColor Red
    LogWrite ""
    $O365AppUserFoundByUPN = $False
    LogWrite "Looking to see if samAccountName '$global:samAccountName' is assigned to Office 365 App Instance: '$($OktaO365App.Id)'..." -FGColor Yellow

    $OktaO365AppUser = GetO365AppUser_samAccountName -AppInstanceId $OktaO365App.Id -samAccountName $global:samAccountName
    If ($OktaO365AppUser -eq $null) {
        LogWrite "ERROR! - Unable to locate Okta user for Office 365 app!" -FGColor Red
        LogWrite ""
        $O365AppUserFoundBysamAccountName = $False
    } else {
        LogWrite "ERROR! - Okta User found by samAccountName for Office 365 App - Okta User ID: $($OktaO365AppUser.Id)" -FGColor Red
        LogWrite ""
        $O365AppUserFoundBysamAccountName = $True
    }
} else {
    LogWrite "Okta User found by UPN for Office 365 App - Okta User ID: $($OktaO365AppUser.Id)" -FGColor Green
    LogWrite ""
    $O365AppUserFoundByUPN = $True
    $O365AppUserFoundBysamAccountName = $null
}   

If (($O365AppUserFoundByUPN -eq $false) -And ($O365AppUserFoundBysamAccountName -eq $False)) {
    LogWrite "Could not find user by Office 365 Username, Looking for Okta User by UPN" -FGColor Yellow
    $OktaUserbyUPN = GetOktaUser_ByUPN -UPN $global:UserUPN
    If ($OktaUserByUPN) {
        LogWrite "Okta User Found by UPN: $Global:UserUPN" -FGColor Green
        LogWrite ""
        LogWrite "Checking to see if User is assigned Office 365 App Instance ID: $($OktaO365App.Id)..." -FGColor Yellow
        $OktaUserO365App = GetOktaUserO365App_ByOktaUserId -UserId $OktaUserbyUPN.Id -O365InstanceId $OktaO365App.Id
        If ($OKtaUserO365App -ne $null) {
            LogWrite "Okta User Id: $(OktaUserByUPN.Id) is assigned Office 365 App Instance $($OktaO365App.Id)" -FGColor Green
            LogWrite ""
            If ($OktaO365AppUser -eq $null) {
                $OktaO365AppUser= $OktaUserO365App  
            }
        } else {
            LogWrite "Okta User Id: $(OktaUserByUPN.Id) not assigned Office 365 App Instance $($OktaO365App.Id)" -FGColor Red
            LogWrite ""
        }

    } else {
        LogWrite "No Okta User found for UPN: $Global:UserUPN" -FGColor Red
        LogWrite ""
    }
}

If ($OktaO365AppUser -ne $null) {
    LogWrite "Office 365 AppUser Profile Data for Okta User $global:UserUpn..." -FGColor Yellow
    LogWrite "Okta User ID               : $($OktaO365AppUser.id)" -FGColor Yellow
    LogWrite "Okta UserName              : $($OktaO365AppUser.profile.displayname)" -FGColor Yellow
    LogWrite "Okta User Status           : $($OktaO365AppUser.Status)" -FGColor Yellow
    LogWrite "Office 365 App Instance ID : $($OktaO365App.Id)" -FGColor Yellow
    LogWrite "Office 365 App Label       : $($OktaO365App.Label)" -FGColor Yellow
    LogWrite "Office 365 App Status      : $($OktaO365App.Status)" -FGColor Yellow
    LogWrite "Office 365 Username        : $($OktaO365AppUser.credentials.username)" -FGColor Yellow
    LogWrite "Office 365 ImmutalbeId     : $($OktaO365AppUser.profile.immutableId)" -FGColor Yellow
    LogWrite "Office 365 ExternalId      : $($OktaO365AppUser.externalId)" -FGColor Yellow
    LogWrite ""
} else {
    LogWrite "Unable to Locate Office 365 App Data for user $global:UserUpn on App Instance Id: $($OktaO365App.Id)..." -FGColor Red
    LogWrite ""
}

LogWrite "Checking Okta System Log for PRT Events for current user..." -FGColor Yellow

#Get System Log Events for PRTs
if ($OktaO365AppUser.id -ne $null) {
    $OktaSystemLogPRTEvents = GetOktaSystemLogPRTEvents -UserId $OktaO365AppUser.id
} else {
    $OktaSystemLogPRTEvents = $null
}

if (($OktaSystemLogPRTEvents.count -gt 0) -or ($OKtaSystemLogPRTEvents -ne $null)) {
    LogWrite "PRT Events found for user" -FGColor Green
    LogWrite ""

    #Get Closed PRT Event
    LogWrite "Looking for PRT Event to match current Widnows Login time $global:CurrentLogonTime UTC..." -FGColor Yellow
    $ClosestOktaLogEvent = $null
    $LeastTimeDiffSecs = $null
    Foreach ($OktaSystemLogPRTEvent in $OktaSystemLogPRTEvents) {
        $LogDate = [datetime]$OktaSystemLogPRTEvent.Published
        $TimeDiff = $global:CurrentLogonTime - $LogDate
        $TimeDiffSecs = [Math]::Abs($TimeDiff.TotalSeconds)
        If (($TimeDiffSecs -lt $LeastTimeDiffSecs) -or ($LeastTimeDiffSecs -eq $null)) {
            $LeastTimeDiffSecs = $TimeDiffSecs
            $ClosestOktaLogEvent = $OktaSystemLogPRTEvent
        }
    }

    if ($LeastTimeDiffSecs -lt 40) {
        LogWrite "PRT Event found with 40 seconds.  DateTime: $([DateTime]$ClosestOktaLogEvent.Published) UTC, Outcome: $($ClosestOktaLogEvent.Outcome.Result)" -FGColor Green
        LogWrite ""
        $OktaSystemLogPRTEvent_Match_WindowsLogin = $ClosestOktaLogEvent
    } else {
        LogWrite "PRT Events found, but none that match with current login time" -FGColor Red
        LogWrite ""
        $OktaSystemLogPRTEvent_Match_WindowsLogin = $null
    }
    
} else{
    LogWrite "PRT Events NOT found for user" -FGColor Red
    LogWrite ""

}

LogWrite "Processing Checklist...." -FGColor Yellow
LogWrite "===============================================" 
LogWrite ""

$ResultsMsg = @()

LogWrite "Check #1 - Device Join Type is Azure-Joined or Hybrid-Joined                       : '$DSRegCmd_JoinType'..." -FGColor Yellow -NoNewLine $True
if (($DSRegCmd_JoinType -match "Hybrid") -or ($DSRegCmd_JoinType -match "AzureAD-Joined")) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#1) Device must be hybrid-joined or azuread-joined. Value: '$DSRegCmd_JoinType'"
}    

LogWrite "Check #2 - UPN Retrieved from Domain (Hybrid) or device                            : '$global:UserUpn'..." -FGColor Yellow -NoNewLine $True
if (($global:UserUpn -match "@") -and ($global:UserUpn -match ".")) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#2) Unable to retrieve email-formatted UPN from Domain (or device). Value: '$global:UserUpn'"
}    

LogWrite "Check #3 - Check Azure AD Tenant Settings, Tenant ID                               : '$DSRegCmd_TenantID'..." -FGColor Yellow -NoNewLine $True
if ($DSRegCmd_TenantID -ne $null) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#3) Azure Tenant Settings are missing. Value: '$DSRegCmd_TenantID'"
}    

LogWrite "Check #4 - Device Exists in Azure,  Device Id                                      : '$($AAD_Device.DeviceId)'..." -FGColor Yellow -NoNewLine $True
if (($AAD_Device -ne $null) -and ($AAD_Device.DeviceId -ne $null)) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#4) Unable to confirm existance of Device Id in Azure Tenant. Value: '$DSRegCmd_DeviceId'"
}    

LogWrite "Check #5 - Azure Device Join Type is Azure-Joined or Hybrid-Joined                 : '$($AAD_Device.Trusttype)'..." -FGColor Yellow -NoNewLine $True
if (($AAD_Device.trusttype -match "ServerAd") -or ($AAD_Device.trusttype -match "AzureAd")) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#5) Azure Join Type is Incorrect.  Must be Hybrid or AzureAD-Joined. Value: '$($AAD_Device.Trusttype)'"
}    

LogWrite "Check #6 - AzureAD-Join/Hybrid Timestamp is before current Windows Login Timestamp : '$AADDeviceJoinTime' UTC..." -FGColor Yellow -NoNewLine $True
if (($AADDeviceJoinTime -ne $null) -and ($AADDeviceJoinTime -lt $global:CurrentLogonTime)) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#6) AzureAD-Join/Hybrid Timestamp was at or after current Windows Login Timestamp. Value: '$global:AAD_Device.Id'"
}    

LogWrite "Check #7 - UserPrincipalName from Device exists in Azure as user                   : '$($AzureUserInfo.UserPrincipalName)'..." -FGColor Yellow -NoNewLine $True
if (($AzureUserInfo.UserPrincipalName -ne $null) -and ($AzureUserInfo.UserPrincipalName -eq $global:UserUPN)) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#7) Unable to confirm existance of User in Azure Tenant by UPN or name does not match local UPN. Value: '$($AzureUserInfo.UserPrincipalName)'"
}    

LogWrite "Check #8 - User is Active in Azure (Login not blocked or disabled)                 : '$($AzureUserInfo.AccountEnabled)'..." -FGColor Yellow -NoNewLine $True
if ($AzureUserInfo.AccountEnabled -eq $true) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#8) User must have AccountEnabled set to True in Azure. Value: '$($AzureUserInfo.AccountEnabled)'"
}    

LogWrite "Check #9 - UPN Domain Suffix is a Federated Domain in Azure                       : '$($AzureFederationInfo.domain_name):$($AzureFederationInfo.account_type)'..." -FGColor Yellow -NoNewLine $True
if (($AzureFederationInfo.account_type -match "Federated") -and ($AzureFederationInfo.domain_name -match $global:DomainName)) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#9) Domain Must be federated in Azure to use Okta as an Identity Provider. Value: '$($AzureFederationInfo.domain_name):$($AzureFederationInfo.account_type)'"
}    

LogWrite "Check #10 - Okta is the Azure Federation Partner for the UPN Domain Suffix         : '$($AzureFederationInfo.federation_active_auth_url)'..." -FGColor Yellow -NoNewLine $True
if (($AzureFederationInfo.federation_active_auth_url -match "okta.com") -and ($OktaActiveAuthUrl -match "okta.com")) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#10) Okta should be the federation partner since this tool is meant to troubleshoot Okta Federation issues with Azure. Value: '$($AzureFederationInfo.federation_active_auth_url)'"
}    

LogWrite "Check #11 - An Office 365 App exists in Okta that is federated for the UPN Domain  : '$($OktaO365App.Id)'..." -FGColor Yellow -NoNewLine $True
if (($OktaO365App.Id -ne $null) -And ($OktaO365App.settings.app.domains.name -contains $AzureFederationInfo.domain_name)) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#11) Unable to locate an Office 365 App in Okta that is federated with Azure for the Domain in the UPN. Value: '$($AzureFederationInfo.domain_name)'"
}    

LogWrite "Check #12 - The discovered Office 365 App has an ACTIVE status                     : '$($OktaO365App.Status)'..." -FGColor Yellow -NoNewLine $True
if ($OktaO365App.Status -match "ACTIVE") {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#12) The Okta Office 365 App must be active and working properly. Value: '$($OktaO365App.Status)'"
}    

LogWrite "Check #13 - UPN was successfully found in lookup against Office 365 App Usernames  : '$($OktaO365AppUser.credentials.username)'..." -FGColor Yellow -NoNewLine $True
if ($OktaO365AppUser.credentials.username -eq $AzureUserInfo.UserPrincipalName) {
    LogWrite "PASSED!" -FGColor Green
} elseif ($OktaO365AppUser.credentials.username -eq $global:samAccountName) {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#13) Assigned user for the Office 365 App is using samAccountName, not UPN. Value: '$($OktaO365AppUser.credentials.username)'"
} elseif ($OktaO365AppUser.credentials.username -ne $null) {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#13) Assigned user for the Office 365 App is not using UPN. Value: '$($OktaO365AppUser.credentials.username)'"
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#13) No assigned user for the Office 365 App has an app username that matches the UPN. Value: '$($OktaO365AppUser.credentials.username)'"
}    

LogWrite "Check #14 - User has ImmutableId value in Azure                                     : '$($AzureUserInfo.onPremisesImmutableId)'..." -FGColor Yellow -NoNewLine $True
if ($AzureUserInfo.onPremisesImmutableId -ne $null) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#14) User must have an ImmutableId in Azure, this means they are synced from AD, or the value was pushed from Okta. Value: '$global:AAD_Device.Id'"
}    

LogWrite "Check #15 - User's ImmutableId in App User Profile matches Azure user profile      : '$($OktaO365AppUser.profile.immutableId)'..." -FGColor Yellow -NoNewLine $True
if ($OktaO365AppUser.profile.immutableId -eq $AzureUserInfo.onPremisesImmutableId) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#15) The ImmutableId in the Okta user's Office 365 app profile must match the value in Azure. Value: '$($OktaO365AppUser.profile.immutableId)'"
}    

LogWrite "Check #16 - An authentication policy was triggered during most recent Win login    : '$($OktaSystemLogPRTEvent_Match_WindowsLogin.Published)' UTC..." -FGColor Yellow -NoNewLine $True
if ($OktaSystemLogPRTEvent_Match_WindowsLogin -ne $null) {
    LogWrite "PASSED!" -FGColor Green
} else {
    LogWrite "MISSING"
    $ResultsMsg += "(#16) A System Log entry was not found in Okta matching this logon attempt.  If any of the checks 1-14 failed, this is expected.  This also is true if Windows Hello for Business was used to login."
}    

LogWrite "Check #17 - Authentication Policy allowed basic auth for Windows Login event       : '$($OktaSystemLogPRTEvent_Match_WindowsLogin.Outcome.Result)'..." -FGColor Yellow -NoNewLine $True
if (($OktaSystemLogPRTEvent_Match_WindowsLogin -ne $null) -And ($OktaSystemLogPRTEvent_Match_WindowsLogin.Outcome.Result -match "ALLOW")) {
    LogWrite "PASSED!" -FGColor Green
} elseif (($OktaSystemLogPRTEvent_Match_WindowsLogin -ne $null) -And ($OktaSystemLogPRTEvent_Match_WindowsLogin.Outcome.Result -notmatch "ALLOW")) {
    LogWrite "FAILED!" -FGColor Red
    $ResultsMsg += "(#17) The Authentication policy during Windows login, but basic auth ws denied.  A policy must exist that allows basic auth with the custom user agent string. Value: '$($OktaSystemLogPRTEvent_Match_WindowsLogin.Outcome.Result)'"
} else {
    LogWrite "MISSING"
    $ResultsMsg += "(#17) No Authentication Policy was evaluated during the current Windows Login event.  If #16 failed, this is expected."
} 

LogWrite ""


#Display Results
Logwrite ""
LogWrite "Analyizing Results...." -FGColor Yellow
LogWrite "===============================================" 
LogWrite ""
$ResultsMsg | Foreach {
    LogWrite $_ -FGColor Red
}
Logwrite ""

Logwrite ""
LogWrite "Notes about results...." -FGColor Yellow
LogWrite "===============================================" 
LogWrite ""
LogWrite "Checks #1-13 - If there are any failures, Okta will not receive an authentication request for PRT" -FGColor Yellow
LogWrite "Checks #14-15 - If these fail, Okta will not send the proper response to Azure for PRT requests" -FGColor Yellow
LogWrite "Check #16-17 - These will be missing if Okta did not receive an authentication request for PRT (Checks #1-13)" -FGColor Yellow

Logwrite ""
Logwrite ""

#>
# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDB60IbBi1w7Txq
# dPlV14beLNQ9jX4Fko9S4hZlbDjp2qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIO5H18XPGJGTTD3HLJZocE1z
# kGANKz4hM+tbodsbl/6uMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0B
# AQEFAASCAQBRT6+iGKAgbKCG5/TeKKYQIbw1WYs3cfPzeUNHC8P92G6YDRYSEMXg
# WMHC5kGMssFhw2wSNeKbSlazPM5CBq3BsFNmQVnNXVN+tfxd6CC5tiTOMwEwdmaT
# N/HJFqNjHMssvEhmZq3mjZjpdz7WMv8zbzVTOjyp/vktytdh+szGdKOKkT2AbP0g
# jXHqajv+62C0eulTWM2JdFVmAJXZA66117yB+B9hFx+i23kE1eeKQR7wqHFIZLoQ
# +0Ue9GXoCntl2izERy+1JRTikSLar+4GHwwB1punPz2G564OYXUWWKJ6Bgmtoccb
# v6vhoNoc0yM33qNVqtbvvcmpxYXpDOhyoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJ/Z4gH5d7GOB1V1OQobYJ/sfSltdXRow79QGVS0pOxoAgZjEV+p
# SFwYEzIwMjIwOTE1MTAzMDA2LjU3NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0Et
# RTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGg6buMuw6i0XoAAQAAAaAwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTIzWhcNMjMwMjI4MTkwNTIzWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC/2uIOaHGdAOj2YvhhI6C8iFAq7wrl/5WpPjj0fEHC
# i6Ivx/I02Jss/HVhkfGTMGttR5jRhhrJXydWDnOmzRU3B4G525T7pwkFNFBXumM/
# 98l5k0U2XiaZ+bulXHe54x6uj/6v5VGFv+0Hh1dyjGUTPaREwS7x98Te5tFHEimP
# a+AsG2mM+n9NwfQRjd1LiECbcCZFkgwbliQ/akiMr1tZmjkDbxtu2aQcXjEfDna8
# JH+wZmfdu0X7k6dJ5WGRFwzZiLOJW4QhAEpeh2c1mmbtAfBnhSPN+E5yULfpfTT2
# wX8RbH6XfAg6sZx8896xq0+gUD9mHy8ZtpdEeE1ZA0HgByDW2rJCbTAJAht71B7R
# z2pPQmg5R3+vSCri8BecSB+Z8mwYL3uOS3R6beUBJ7iE4rPS9WC1w1fZR7K44ZSm
# e2dI+O9/nhgb3MLYgm6zx3HhtLoGhGVPL+WoDkMnt93IGoO6kNBCM2X+Cs22ql2t
# PjkIRyxwxF6RsXh/QHnhKJgBzfO+e84I3TYbI0i29zATL6yHOv5sEs1zaNMih27I
# wfWg4Q7+40L7e68uC6yD8EUEpaD2s2T59NhSauTzCEnAp5YrSscc9MQVIi7g+5GA
# dC8pCv+0iRa7QIvalU+9lWgkyABU/niFHWPjyGoB4x3Kzo3tXB6aC3yZ/dTRXpJn
# aQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFHK5LlDYKU6RuJFsFC9EzwthjNDoMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBADF9xgKr+N+slAmlbcEqQBlpL5PfBMqcLkS6ySeGJjG+LKX3Wov5pygrhKft
# XZ90NYWUftIZpzdYs4ehR5RlaE3eYubWlcNlwsKkcrGSDJKawbbDGfvO4h/1L13s
# g66hPib67mG96CAqRVF0c5MA1wiKjjl/5gfrbdNLHgtREQ8zCpbK4+66l1Fd0up9
# mxcOEEphhJr8U3whwFwoK+QJ/kxWogGtfDiaq6RyoFWhP8uKSLVDV+MTETHZb3p2
# OwnBWE1W6071XDKdxRkN/pAEZ15E1LJNv9iYo1l1P/RdF+IzpMLGDAf/PlVvTUw3
# VrH9uaqbYr+rRxti+bM3ab1wv9v3xRLc+wPoniSxW2p69DN4Wo96IDFZIkLR+HcW
# CiqHVwFXngkCUfdMe3xmvOIXYRkTK0P6wPLfC+Os7oeVReMj2TA1QMMkgZ+rhPO0
# 7iW7N57zABvMiHJQdHRMeK3FBgR4faEvTjUAdKRQkKFV82uE7w0UMnseJfX7ELDY
# 9T4aWx2qwEqam9l7GHX4A2Zm0nn1oaa/YxczJ7gIVERSGSOWLwEMxcFqBGPm9QSQ
# 7ogMBn5WHwkdTTkmanBb/Z2cDpxBxd1vOjyIm4BOFlLjB4pivClO2ZksWKH7qBYl
# oYa07U1O3C8jtbzGUdHyLCaVGBV8DfD5h8eOnyjraBG7PNNZMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAEwa4jWjacbOYU++95ydJ7hSCi5ig
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAObNAWYwIhgPMjAyMjA5MTUwOTQxNThaGA8yMDIyMDkxNjA5NDE1OFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5s0BZgIBADAKAgEAAgILrwIB/zAHAgEA
# AgISHzAKAgUA5s5S5gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAAMKBzKr
# 03t114p50znSJtoR0z66H9qiHHO/Sn2GVScCwenHYe3aSYe9MV8AgEe5G1PP5max
# lAPb7xXZH/y7VOZhNZr4WxnydORkIvVRQJNyxXiSKmavUsiuqXLh46h07733A0lB
# PKA+YNWXHTiuxlU9xNfzAfglQ95iYy3YagFmMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGg6buMuw6i0XoAAQAAAaAwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgNDmobcp32IR+/JLau3ztgIUQnuQUnLpvrl0fklk5mwwwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAvR4o8aGUEIhIt3REvsx0+svnM6Wia
# ga5SPaK4g6+00zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABoOm7jLsOotF6AAEAAAGgMCIEIISLjExjsjGPRPPZawR7ogVfpbrJy0Fr
# klqHlUGu9HVIMA0GCSqGSIb3DQEBCwUABIICAHgxtT3bPqzR9UzBAkJ5STVXh9/+
# 1uJiTmP8zVWE7ld7d07DK6eiqRJK6cdtPCugARzls9XbncGtQ+nv0WpolFCgXzgb
# 2eY6/mxsNCC9ul/OS/yuSBjs1yLB+GZl2s6KTZ6V4RjrrQI0BBEu8c0IDYoCMxpy
# YSpUQimbKn4xycXNK8Z3cUthiMvNvI7mgvcdepqlaNzdgeuJ3PEO6HABOxjSI2Sc
# 3PcMXlM0Dy+lhQBVIstt6cPoYMhb/kcMxXbyP6wtFWuAjF4hDkMzJTovI1UfKja4
# fGvPvSOCg4qGeJ9j39RbnSSdr7TXThs9DymtCDTQ8vV3sQ3B6AUvxdLu/QKd2dru
# vOadhKI32X4ULDzp/OnMoAaBUUZbVHSYsojgaf9JiX8pGppMo9mz6f0uEEukjOX1
# W7+fTM6YIEKUUNsfWoIy2am4lqEsEppuccTHfU78cobRIY5dzRo8VBemZNQwcoP8
# xA2rOr84mIOuzxH1NWHHMRBurgzRFLOG09iFnIikNc1x1VnhRTJsgwOdarSzkLL7
# UyivsTL8Qu6BgoR5vrEL1ukTrtE3K3t+8IZ8KGRFg/gEwsFDp1FiK0rLF5Y7V7Lg
# B46gZV4Ptliqj3F2camjN//gQmygnGo74+qvHKTp4PA2GNjQ2d4evUNeuITiP1U0
# d1vEDfL1OCWICh6/
# SIG # End signature block
