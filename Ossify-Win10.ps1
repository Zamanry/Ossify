# Initially created by Zamanry, 05/2018

#Customizing Context Menus:

#Removal of 'Send to'
Set-ItemProperty -Path "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Send To" -Name (Default) -Value $NULL -Force 

#Addition of 'Open PowerShell here'
New-Item -Path HKEY_CLASSES_ROOT\Directory\shell -name PowerShellMenu -Type Directory
Set-ItemProperty -Path HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu -Name (Default) -Value "Open PowerShell here" 
New-Item -Path HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu' -name 'command -Type Directory
Set-ItemProperty -Path HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu\command -Name (Default) -Value "C:\Windows\System32\WindowsPowerShell\v1.0 -NoExit -Command Set-Location -LiteralPath '%L'"

#Removal of 'Personalize'
Import-Module -Name .\Set-Owner.psm1
Set-Owner -Path "HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize" -Recurse
Remove-item -Path HKEY_CLASSES_ROOT\DesktopBackground\Shell -name Personalize

#Removal of 'Display'
Set-Owner -Path HKEY_CLASSES_ROOT\DesktopBackground\Shell\Display -Recurse
Remove-item -Path HKEY_CLASSES_ROOT\DesktopBackground\Shell -name Display

#Flush DNS
Ipconfig /flushdns

#Removal of built-in apps:
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

do
{
    Get-AppxPackage -Name $Apps -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    $Index++
    $CrntApp = $Apps[$Index]

}
while ($CrntApp -ne $NULL)

#Disable unnecessary network components
Write-Host Disabling network components.
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_tcpip6'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_rspndr'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_lltdio'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_implat'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_msclient'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_pacer'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_server'

#Disable IPv6 completely
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Type DWORD -Value "0xFF" -Force 

#Disable 'Register this connection's addresses in DNS'
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
$NIC.SetDynamicDNSRegistration($false)

#Disable NetBIOS over TCP/IP
$NIC.SetTcpipNetbios(2)

#Disable LMHosts lookup
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration'
$NIC.enablewins($false,$false)

#Disables IGMP
Netsh interface ipv4 set global mldlevel = none

#Disable memory dumps
Wmic recoveros set DebugInfoType = 0

#Disable File Explorer Sharing Wizard
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Value 0

#Disable PCT 1.0
DisableProtocol("PCT 1.0")

#Disable SSL 2.0
DisableProtocol("SSL 2.0")

#Disable SSL 3.0
DisableProtocol("SSL 3.0")

#Disable TLS 1.0
DisableProtocol("TLS 1.0")

#Disable TLS 1.1
DisableProtocol("TLS 1.1")

#Enable TLS 1.2 (No other SSL or TLS versions are enabled)
if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl" == false)
{
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -name "$Prtcrl" -Type Directory
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl" -name "Client" -Type Directory
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl" -name "Server" -Type Directory
}
else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl\Client" == false)
{
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl" -name "Client" -Type Directory
}
else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl\Server" == false)
{
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl" -name "Server" -Type Directory
}
else
{
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl\Client" -Type DWORD -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl\Client" -Type DWORD -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl\Server" -Type DWORD -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Prtcrl\Server" -Type DWORD -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type DWORD -Name "DefaultSecureProtocols" -Value 0x00000800
    
    #Force .NET Framework 4.0 to use TLS 1.2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1
}

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
