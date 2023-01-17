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
        LogWrite "$_.Exception.Message"
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
        LogWrite "$_.Exception.Message"
    }

    #Get Office 365 App for User
    $OktaOffice365InstanceId = $Null

    if ($OktaO365Apps.count -gt 0) {
        #Check for Active
        $OktaO365Apps_Active = $OktaO365Apps | Where-Object {$_.status -eq "ACTIVE"}
        $OktaO365Apps_Active | Foreach {
            if (($_.settings.app.domain -match $Domain) -And ($OktaOffice365InstanceId -eq $null)) {
                $OktaOffice365InstanceId = $_.Id
            } elseif (($_.settings.app.domains.name -match $Domain) -And ($OktaOffice365InstanceId -eq $null)) {
                    $OktaOffice365InstanceId = $_.Id
            }
        }
    
        if ($OktaOffice365InstanceId -eq $null) {
            #No Active app, Check All Apps
            LogWrite "No Active Office365 App Found for domain: $Domain" -FGColor Red
            $OktaO365Apps | Foreach {
                if (($_.settings.app.domain -match $Domain) -And ($OktaOffice365InstanceId -eq $null)) {
                    $OktaOffice365InstanceId = $_.Id
                } elseif (($_.settings.app.domains.name -match $Domain) -And ($OktaOffice365InstanceId -eq $null)) {
                        $OktaOffice365InstanceId = $_.Id
                }
            }
        }    
    } else {
        LogWrite "NO OFFICE 365 APPS FOUND!" -FGColor Red
        LogWrite ""
    }

    If ($OktaOffice365InstanceId -ne $null) {
        $OktaO365AppsUrl = "$global:OktaTenantUrl/api/v1/apps/$OktaOffice365InstanceId"
        try {
            $OktaO365AppsJson = Invoke-WebRequest -uri $OktaO365AppsUrl -Headers $global:OktaHeaders -UseBasicParsing -Method "GET" -ContentType "application/json"
            $OktaO365App = $OktaO365AppsJson.Content | ConvertFrom-Json
        } catch {
            LogWrite "$_.Exception.Message"
            $OktaOffice365InstanceId = $Null
            $OktaO365App = $null
        }
    } else {
        $OktaO365App = $null
    }
#>
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
            LogWrite "$_.Exception.Message"
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
            LogWrite "$_.Exception.Message"
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
        LogWrite "$_.Exception.Message"
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
        LogWrite "$_.Exception.Message"
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
        LogWrite "$_.Exception.Message"
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
if ($AzureFederationInfo.account_type -match "Federated") {
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
if ($OktaO365App.Id -ne $null) {
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
if ($ResultsMsg.count -gt 0) {
    $ResultsMsg | Foreach {
        LogWrite $_ -FGColor Red
    }    
} else {
LogWrite "All Checks Passed!" - FGColor Green
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
