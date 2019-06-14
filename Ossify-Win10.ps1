Write-Output "##################################################"
Write-Output "#                                                #"
Write-Output '#    .aMMMb  .dMMMb  .dMMMb  dMP dMMMMMP dMP dMP #'
Write-Output '#   dMP"dMP dMP" VP dMP" VP amr dMP     dMP.dMP  #'
Write-Output '#  dMP dMP  VMMMb   VMMMb  dMP dMMMP    VMMMMP   #'
Write-Output '# dMP.aMP dP .dMP dP .dMP dMP dMP     dA .dMP    #'
Write-Output '# VMMMP"  VMMMP"  VMMMP" dMP dMP      VMMMP"     #'
Write-Output "#                                                #"
Write-Output "# Written by Zamanry.                            #"
Write-Output "##################################################"

###################################################
Write-Output "Customizing Context Menus..."

#Removes 'Send to'
Set-ItemProperty -Path "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Send To" -Name (Default) -Value $NULL -Force 

#Adds 'Open PowerShell here'
New-Item -Path HKEY_CLASSES_ROOT\Directory\shell -name PowerShellMenu -Type Directory
Set-ItemProperty -Path HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu -Name (Default) -Value "Open PowerShell here" 
New-Item -Path HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu' -name 'command -Type Directory
Set-ItemProperty -Path HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu\command -Name (Default) -Value "C:\Windows\System32\WindowsPowerShell\v1.0 -NoExit -Command Set-Location -LiteralPath '%L'"

#Removes 'Personalize'
Import-Module -Name .\Set-Owner.psm1
Set-Owner -Path "HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize" -Recurse
Remove-item -Path HKEY_CLASSES_ROOT\DesktopBackground\Shell -name Personalize

#Removes 'Display'
Set-Owner -Path HKEY_CLASSES_ROOT\DesktopBackground\Shell\Display -Recurse
Remove-item -Path HKEY_CLASSES_ROOT\DesktopBackground\Shell -name Display

Write-Output "Done."

###################################################
Write-Ouput "Flushing..."

#Flushes DNS
Ipconfig /flushdns

Write-Output "Done."

###################################################
Write-Output "Removing bloatware..."

#Removes built-in apps:
$Apps =
'Microsoft.3DBuilder',
'Microsoft.Appconnector',
'Microsoft.BingFinance',
'Microsoft.BingNews',
'Microsoft.BingSports',
'Microsoft.BingTranslator',
'Microsoft.BingWeather',
'Microsoft.FreshPaint',
'Microsoft.Microsoft3DViewer',
'Microsoft.MicrosoftOfficeHub',
'Microsoft.MicrosoftSolitaireCollection',
'Microsoft.MicrosoftPowerBIForWindows',
'Microsoft.MinecraftUWP',
'Microsoft.MicrosoftStickyNotes',
'Microsoft.NetworkSpeedTest',
'Microsoft.Office.OneNote',
'Microsoft.OneConnect',
'Microsoft.People',
'Microsoft.Print3D',
'Microsoft.SkypeApp',
'Microsoft.Wallet',
'Microsoft.WindowsAlarms',
'Microsoft.WindowsCamera',
'Microsoft.windowscommunicationsapps',
'Microsoft.WindowsMaps',
'Microsoft.WindowsPhone',
'Microsoft.WindowsSoundRecorder',
'Microsoft.XboxApp',
'Microsoft.XboxGameOverlay',
'Microsoft.XboxIdentityProvider',
'Microsoft.XboxSpeechToTextOverlay',
'Microsoft.ZuneMusic',
'Microsoft.ZuneVideo',
'Microsoft.CommsPhone',
'Microsoft.ConnectivityStore',
'Microsoft.GetHelp',
'Microsoft.Getstarted',
'Microsoft.Messaging',
'Microsoft.Office.Sway',
'Microsoft.OneConnect',
'Microsoft.WindowsFeedbackHub',
'Microsoft.Microsoft3DViewer',
'Microsoft.BingFoodAndDrink',
'Microsoft.BingTravel',
'Microsoft.BingHealthAndFitness',
'Microsoft.WindowsReadingList',
'9E2F88E3.Twitter',
'PandoraMediaInc.29680B314EFC2',
'Flipboard.Flipboard',
'ShazamEntertainmentLtd.Shazam',
'king.com.CandyCrushSaga',
'king.com.CandyCrushSodaSaga',
'king.com.*',
'ClearChannelRadioDigital.iHeartRadio',
'4DF9E0F8.Netflix',
'6Wunderkinder.Wunderlist',
'Drawboard.DrawboardPDF',
'2FE3CB00.PicsArt-PhotoStudio',
'D52A8D61.FarmVille2CountryEscape',
'TuneIn.TuneInRadio',
'GAMELOFTSA.Asphalt8Airborne',
'TheNewYorkTimes.NYTCrossword',
'DB6EA5DB.CyberLinkMediaSuiteEssentials',
'Facebook.Facebook',
'flaregamesGmbH.RoyalRevolt2',
'Playtika.CaesarsSlotsFreeCasino',
'A278AB0D.MarchofEmpires',
'KeeperSecurityInc.Keeper',
'ThumbmunkeysLtd.PhototasticCollage',
'XINGAG.XING',
'89006A2E.AutodeskSketchBook',
'D5EA27B7.Duolingo-LearnLanguagesforFree',
'46928bounde.EclipseManager',
'ActiproSoftwareLLC.562882FEEB491',
'DolbyLaboratories.DolbyAccess',
'SpotifyAB.SpotifyMusic',
'A278AB0D.DisneyMagicKingdoms',
'WinZipComputing.WinZipUniversal'

$Index = 0
$CrntApp = $Apps[$Index]

do {
    Get-AppxPackage -Name $Apps -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    $Index++
    $CrntApp = $Apps[$Index]
} while ($CrntApp -ne $NULL)

Write-Output "Done."

###################################################
Write-Output "Reducing network connections..."

#Disables unnecessary network components
Write-Host Disabling network components.
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_tcpip6'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_rspndr'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_lltdio'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_implat'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_msclient'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_pacer'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_server'

#Disables IPv6 completely
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Type DWORD -Value "0xFF" -Force 

#Disables 'Register this connection's addresses in DNS'
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
$NIC.SetDynamicDNSRegistration($false)

#Disables NetBIOS over TCP/IP
$NIC.SetTcpipNetbios(2)

#Disables LMHosts lookup
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration'
$NIC.enablewins($false,$false)

#Disables IGMP
Netsh interface ipv4 set global mldlevel = none

Write-Output "Done."

###################################################
Write-Output "Disabling unnecessary protocols..."

DisableProtocol() {
    if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" == false) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -name "$Protocol" -Type Directory
    }
    else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" == false) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Client" -Type Directory
    }
    else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" == false) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Server" -Type Directory
    }
    else {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocoll\Client" -Type DWORD -Name "DisabledByDefault" -Value 1
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Type DWORD -Name "Enabled" -Value 0
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" -Type DWORD -Name "DisabledByDefault" -Value 1
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" -Type DWORD -Name "Enabled" -Value 0
    }
}

#Disables PCT 1.0
$Protocol = "PCT 1.0"
DisableProtocol()

#Disables SSL 2.0
$Protocol = "SSL 2.0"
DisableProtocol()

#Disables SSL 3.0
$Protocol = "SSL 3.0"
DisableProtocol()

#Disables TLS 1.0
$Protocol = "TLS 1.0"
DisableProtocol()

#Disables TLS 1.1
$Protocol = "TLS 1.1"
DisableProtocol()

#Enables TLS 1.2 (No other SSL or TLS versions are enabled)
$Protocol = "TLS 1.2"
if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" == false) {
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -name "$Protocol" -Type Directory
}
else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" == false) {
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Client" -Type Directory
}
else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" == false) {
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Server" -Type Directory
}
else {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocoll\Client" -Type DWORD -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Type DWORD -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" -Type DWORD -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" -Type DWORD -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type DWORD -Name "DefaultSecureProtocols" -Value 0x00000800
    
    #Force .NET Framework 4.0 to use TLS 1.2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1
}

Write-Output "Done."

###################################################
Write-Output "Performing miscellaneous tweaks..."

#Disables memory dumps
Wmic recoveros set DebugInfoType = 0

#Disables File Explorer Sharing Wizard
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Value 0

Write-Output "Done."

###################################################
Write-Output "Performing miscellaneous tweaks..."

# Calls the desired tweak functions
Import-Module .\Tweaks.psm1
$tweaks | ForEach { Invoke-Expression $_ }

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
