Start-Transcript -Path "$env:UserProfile\Desktop\PS-Initial-Script.log" -Append -IncludeInvocationHeader -NoClobber
Set-StrictMode -Version 'Latest'
Write-Host ''
Write-Host '##############################################'
Write-Host '#                                            #'
Write-Host '#    .aMMMb .dMMMb .dMMMb dMP dMMMMMPdMP dMP #'
Write-Host '#   dMP*dMPdMP* VPdMP* VPamr dMP*   dMP.dMP  #'
Write-Host '#  dMP dMP VMMMb  VMMMb dMP dMMMP   VMMMMP   #'
Write-Host '# dMP.aMPdP .dMPdP .dMPdMP dMP    dA .dMP    #'
Write-Host '# VMMMP" VMMMP" VMMMP"dMP dMP     VMMMP"     #'
Write-Host '#                                            #'
Write-Host '###################Zamanry####################'
Write-Host ''

#################################################################
Write-Host 'Have you edited your settings in Tweaks.psm1 first?'
	Set-Variable -Name 'UserResponse' -Value (Read-Host -Prompt '(Y/n)')
	If (($UserResponse -eq 'Y') -or ($UserResponse -eq 'y')) {
		Write-Host 'Continuing Ossify...'
	}
	Else {
		Write-Host 'Please edit Tweaks.psm1 first before running. Exiting Ossify...'
		Exit
	}

#################################################################
Write-Host 'Customizing Context Menus...'
	Set-ItemProperty -Path 'HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Send To' -Name '(Default)' -Value $NULL -Force # Removes 'Send to'
	New-Item -Path 'HKEY_CLASSES_ROOT\Directory\shell' -Name 'PowerShellMenu' -Type 'Directory' # Adds 'Open PowerShell'
	Set-ItemProperty -Path 'HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu' -Name '(Default)' -Value 'Open PowerShell' # Adds 'Open PowerShell'
	New-Item -Path 'HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu' -Name 'command' -Type 'Directory' # Adds 'Open PowerShell'
	Set-ItemProperty -Path 'HKEY_CLASSES_ROOT\Directory\shell\PowerShellMenu\command' -Name '(Default)' -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0" -NoExit -Command 'Set-Location' -LiteralPath '%L' # Adds 'Open PowerShell'
	Import-Module -Name '.\Set-Owner.psm1' # Removes 'Personalize'
	Set-Owner -Path 'HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize' -Recurse # Removes 'Personalize'
	Remove-item -Path 'HKEY_CLASSES_ROOT\DesktopBackground\Shell' -Name 'Personalize' # Removes 'Personalize'
	Set-Owner -Path 'HKEY_CLASSES_ROOT\DesktopBackground\Shell\Display' -Recurse # Removes 'Display'
	Remove-item -Path 'HKEY_CLASSES_ROOT\DesktopBackground\Shell' -Name 'Display' # Removes 'Display'
	Write-Host 'Done.'

#################################################################
Write-Host 'Flushing caches...'
	Ipconfig /flushdns
	netsh interface ipv4 delete arpcache
	netsh interface ipv4 delete destinationcache
	netsh interface ipv4 delete neighbors
	Set-Variable -Name 'Adapter' -Value (Get-NetAdapter -Name 'Ethernet*' -Physical | Select-Object -ExpandProperty 'Name')
	netsh interface ipv4 delete winsservers $Adapter all
	Remove-Item -Path "$env:SystemRoot\System32\drivers\etc\hosts" -force
	New-Item -Path "$env:SystemRoot\System32\drivers\etc" -Name 'hosts' -ItemType 'file' -Value '# Flushed.' -Force
	Write-Host 'Done.'

#################################################################
Write-Host 'Removing bloatware...'
	[Array]$Apps =
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
		'A278AB0D.DisneyMagicKingdoms',
		'WinZipComputing.WinZipUniversal',
		'Microsoft.ScreenSketch',
		'Microsoft.XboxGamingOverlay',
		'Microsoft.YourPhone'
	Foreach ($App in $Apps) {
		Get-AppxPackage $App | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue'
	}
	Write-Host 'Done.'

#################################################################
Write-Host 'Disabling unnecessary network connections...'
	netsh Interface IPv4 Set Global mldlevel=none # Disables IGMPLevel
	New-Item -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Value '0xFF' # Disables IPv6 completely
	New-Item -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value '0' # Disables Remote Assistance
	New-Item -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value '1' # Disables Remote Desktop
	Get-NetAdapter -Name '*' | Set-DNSClient -Interface $_ -RegisterThisConnectionsAddress $FALSE # Disables 'Register this connection's addresses in DNS'
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_lldp' # Microsoft LLDP Protocol Driver
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_implat' # Microsoft Network Adapter Multiplexor Protocol
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_lltdio' # Link-Layer Topology Discovery Mapper I/O Driver
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_tcpip6' # Internet Protocol Version 6 (TCP/IPv6)
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_server' # File and Printer Sharing for Micorsoft Networks
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_rspndr' # Link-Layer Topology Discovery Responder
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_msclient' # Client for Microsft Networks
	Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_pacer' # QoS a Scheduler
	Set-Variable -Name 'Adapter' -Value (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'ipenabled = 'true'')
	$Adapter.SetTCPIPNetBIOS(2) # Disables NetBIOS over TCP/IP
	$AdapterClass.EnableWINS($FALSE,$FALSE) # Disables WINS
	Remove-Variable -Name 'Adapter', 'AdapterClass'
	Write-Host 'Done.'

#################################################################
Write-Host 'Disabling unnecessary protocols...'
	Set-Variable -Name 'Path' -Value 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
	$Protocols = @('DTLS 1.0', 'PCT 1.0', 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
	Foreach ($Protocol in $Protocols) {
		New-Item -Path $Path -Name $Protocol -Type 'Directory' -ErrorAction 'SilentlyContinue'
		Set-Variable -Name 'Path' -Value $Path\$Protocol
		New-Item -Path $Path -Name 'Client' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path $Path -Name 'Server' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Client" -Name 'DisabledByDefault' -Value '1'
		New-Item -Path "$Path\Client" -Name 'Enabled' -Value '0'
		New-Item -Path "$Path\Server" -Name 'DisabledByDefault' -Value '1'
		New-Item -Path "$Path\Client" -Name 'Enabled' -Value '0'
	}
	Set-SmbServerConfiguration -EnableSMB2Protocol $FALSE -Force
	Write-Host 'Done.'

#################################################################
Write-Host 'Enabling TLSv1.2...'
	Set-Variable -Name 'Path' -Value 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
	Set-Variable -Name 'Protocol' -Value 'TLS 1.2'
	New-Item -Path $Path -Name $Protocol -Type 'Directory' -ErrorAction 'SilentlyContinue'
	New-Item -Path $Path -Name 'Client' -Type 'Directory' -ErrorAction 'SilentlyContinue'
	New-Item -Path $Path -Name 'Server' -Type 'Directory' -ErrorAction 'SilentlyContinue'
	New-item -Path "$Path\Client" -Name 'DisabledByDefault' -Value '0'
	New-item -Path "$Path\Client" -Name 'Enabled' -Value '1'
	New-item -Path "$Path\Server" -Name 'DisabledByDefault' -Value '0'
	New-item -Path "$Path\Server" -Name 'Enabled' -Value '1'
	New-item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols' -Value '0x800'
	New-item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols' -Value '0x800'
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'SecureProtocols' -Value '0x800'
	New-item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'chUseStrongCrypto' -Value '1'
	New-item -Path 'Registry::HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'chUseStrongCrypto' -Value '1'
	Write-Host 'Done.'

#################################################################
Write-Host 'Correcting registry keys...'
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value '0' # Displays file extensions
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SharingWizardOn' -Value '0' # Disables Sharing Wizard
	net accounts /maxpwage:30 /minpwage:0 /minplen:10 /lockoutthreshold:5 /uniquepw:2 # Sets user password restrictions
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Value 'UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED.' # Sets login screen MOTD
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -Value 'You must have explicit authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities on this device are logged and monitored.' # Sets login screen MOTD
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Value '1' # Disables password display button
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisablePasswordReveal' -Value '1' # Disables password display button
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Value '1' # Disables password display button
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Value '1' # Disables Windows Connect Now wizard
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\common\services\fax' -Name 'nofax' -Value '1' # Disables online Fax services
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\access\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\excel\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\excel\security' -Name 'blockcontentexecutionfrominternet' -Value '1' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\excel\security' -Name 'excelbypassencryptedmacroscan' -Value '0' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\ms project\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\ms project\security' -Name 'level' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\outlook\security' -Name 'level' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\powerpoint\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\powerpoint\security' -Name 'blockcontentexecutionfrominternet' -Value '1' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\publisher\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\visio\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\visio\security' -Name 'blockcontentexecutionfrominternet' -Value '1' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\word\security' -Name 'vbawarnings' -Value '4' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\word\security' -Name 'blockcontentexecutionfrominternet' -Value '1' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\word\security' -Name 'wordbypassencryptedmacroscan' -Value '0' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\common\security' -Name 'automationsecurity' -Value '3' # Blocks Macros and other content execution
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\outlook\options\mail' -Name 'blockextcontent' -Value '1' # Disables external content by default in Outlook emails
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\office\16.0\outlook\options\mail' -Name 'junkmailenablelinks' -Value '0' # Disables external content by default in Outlook emails
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP' -Name 'CEIPEnable' -Value '0' # Disables CEIP for apps and generally
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value '0' # Disables CEIP for apps and generally
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\PushToInstall' -Name 'DisablePushToInstall' -Value '1' # Disables pushing of apps for installation from the Windows store
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Value '1' # Disables pushing of apps for installation from the Windows store
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'AllowProjectionToPC' -Value '0' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'RequirePinForPairing' -Value '1' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\WirelessDisplay' -Name 'EnforcePinBasedPairing' -Value '1' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings' -Name 'NoPresentationSettings' -Value '1' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value '1' # Disables Autorun
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value '255' # Disables Autorun
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortanaAboveLock' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Value '1' # Disables Cortana
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Value '1' # Disables Autoplay
	New-Item -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value '506' # Disables Sticky keys
	Write-Host 'Done.'

#################################################################
Write-Host 'Configuring Internet options...'
	# Misc. tabs
		Set-Variable -Name 'Path' -Value 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Scope 'Script'
		Set-Variable -Name 'Path1' -Value 'Registry::HKCU\Software\Microsoft\Internet Explorer' -Scope 'Script'
		New-Item -Path "$Path1\Main" -Name 'Start Page' -Value 'https://google.com' # Home page
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'WarnOnClose' -Value '0' # Warn me when closing multiple tabs: No
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'NetTabPageShow' -Value '1' # When a new tab is opened, open: A blank page
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'PopupsUseNewWindow' -Value '0' # When a pop-up is encountered: Let IE decide
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'ShortcutBehavior' -Value '1' # Open links from other programs in: A new tab
		New-Item -Path $Path1 -Name 'Privacy' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Privacy" -Name 'ClearBrowsingHistoryOnExit' -Value '1' # Delete browsing history on exit: Yes
		New-Item -Path $Path1 -Name 'ContinuousBrowsing' -Value '0' # Delete browsing history on exit: Yes
		New-Item -Path $Path -Name 'SyncMode5' -Value '0' # Check for newer versions of stored pages: Never
		New-Item -Path "$Path\5.0\Cache\Content" -Name "CacheLimit" -Value '8192' # Disk space to use (Website caches): Minimum of 8 mB
		New-Item -Path $Path -Name 'Url History' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Url History" -Name 'DaysToKeep' -Value '0' # Days to keep pages in history: 0
		New-Item -Path $Path1 -Name 'BrowserStorage' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\BrowserStorage" -Name 'IndexedDB' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\BrowserStorage\IndexedDB" -Name 'AllowWebsiteDatabases' -Value '0' # Allow website caches and databases
		New-Item -Path "$Path1\BrowserStorage" -Name 'AppCache' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\BrowserStorage\AppCache" -Name 'AllowWebsiteCaches' -Value '0' # Allow website caches and databases
	# Privacy Tab
		New-Item -Path $Path1 -Name 'Geolocation' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Geolocation" -Name 'BlockAllWebsites' -Value '1' # Never allow websites to request your physical location
		New-Item -Path "$Path1\New Windows" -Name 'PopupMgr' -Value '1' # Turn on Pop-up Blocker
		New-Item -Path "$Path1\New Windows" -Name 'BlockUserInit' -Value '1' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'UseTimerMethod' -Value '0' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'UseHooks' -Value '0' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'AllowHTTPS' -Value '0' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'BlockControls' -Value '1' # Blocking level: High: Block all pop-ups
		New-Item -Path $Path1 -Name 'Safety' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Safety" -Name 'PrivacIE' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Safety\PrivacIE" -Name 'DisableToolbars' -Value '1' # Disable toolbars and extensions when InPrivate Browsing starts
	# Programs Tab
		New-Item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{2933BF90-7B36-11D2-B20E-00C04F983E60}\iexplore' -Name 'Flags' -Value '4' #Disable XML DOM Document extension
		New-Item -Path $Path -Name 'Activities' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities" -Name 'Email' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Email" -Name 'live.com' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Email\live.com" -Name 'Enabled' -Value '0' # Disable E-mail with Windows Live accelerator
		New-Item -Path "$Path\Activities" -Name 'Map' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Map" -Name 'bing.com' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Map\bing.com" -Name 'Enabled' -Value '0' # Disable Map with Bing accelerator
		New-Item -Path "$Path\Activities" -Name 'Translate' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Translate" -Name 'microsofttranslator.com' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Translate\microsofttranslator.com" -Name 'Enabled' -Value '0' # Disable Translate with Bing accelerator
	# Advanced tab
		New-Item -Path "$Path1\Main" -Name 'DisableScriptDebuggerIE' -Value 'yes' # Disable script debugging (Internet Explorer): Yes
		New-Item -Path "$Path1\Main" -Name 'Disables Script Debugger' -Value 'yes' # Disable script debugging (Other): Yes
		New-Item -Path "$Path1\Recovery" -Name 'AutoRecover' -Value '2' # Enable automatic crash recovery: No
		New-Item -Path 'Registry::HKCU\Software\Microsoft\FTP' -Name 'Use Web Based FTP' -Value 'yes' # Enable FTP folder view: No
		New-Item -Path "$Path1\Main" -Name 'Enable Browser Extensions' -Value '0' # Enable third-party browser extensions: No
		New-Item -Path 'Registry::HKCU\Software\Microsoft\FTP' -Name 'Use PASV' -Value 'no' # Use Passive FTP: No
		New-Item -Path $Path -Name 'EnableHttp1_1' -Value '0' # Use HTTP 1.1: No
		New-Item -Path $Path -Name 'ProxyHttp1.1' -Value '0' # Use HTTP 1.1 through proxy connections: No
		New-Item -Path $Path -Name 'EnableHTTP2' -Value '1' # Use HTTP2
		New-Item -Path "$Path1\Main" -Name 'FeatureControl' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Main\FeatureControl" -Name 'FEATURE_LOCALMACHINE_LOCKDOWN' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name 'Settings' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -Name 'LOCALMACHINE_CD_UNLOCK' -Value '0' # Allow content from CDs...: No
		New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name 'iexplore.exe' -Value '1' # Allow content from my files...: No
		New-Item -Path $Path1 -Name 'Download' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Download" -Name 'RunInvalidSignatures' -Value '0' # Allow software to run if invalid: No
		New-Item -Path "$Path1\Main" -Name 'MixedContentBlockImages' -Value '1' # Block unsecure images with other content: Yes
		New-Item -Path $Path -Name 'CertificateRevocation' -Value '1' # Check for publisher/server's certificate revocation: Yes
		New-Item -Path "$Path1\Download" -Name 'CheckExe' -Value 'yes' # Check for signatures on downloaded programs: Yes
		New-Item -Path "$Path1\Main" -Name 'XMLHTTP' -Value '0' # Enable XMLHTTP support: No
		New-Item -Path "$Path1\PhishingFilter" -Name 'Enabledv9' -Value '1' # Enable Widows Defender SmartScreen: Yes
		New-Item -Path "$Path1\Main" -Name 'DoNotTrack' -Value '1' # Enable Do Not Track requests: Yes
		New-Item -Path $Path -Name 'WarnonBadCertRecving' -Value '1' # Warn about certificate address mismatch: Yes
		New-Item -Path $Path -Name 'WarnonZoneCrossing' -Value '1' # Warn if changing between secure/not secure modes: Yes
		New-Item -Path $Path -Name 'WarnOnPostRedirect' -Value '1' # Warn if POST submittal is redirected...: Yes

#################################################################
Write-Warning 'Setting UAC level to High...'
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value '2'
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value '1'
	Write-Host 'Done.'

#################################################################
Write-Warning 'Disabling Windows services...'
	[Array]$Services =
		'lmhosts', # TCP/IP NetBIOS Helper
		'wlidsvc', # Microsoft Account Sign-in Assistant
		'SEMgrSvc', # Payments NFC/SE Manager
		'tzautoupdate', # Auto Time Zone Updater
		'AppVClient', # Microsoft App-V Client
		'RemoteRegistry', # Remote Registry
		'RemoteAccess', # Routing & Remote Access
		'shpamsvc', # Shared PC Account Manager
		'UevAgentService', # User Experience Virtualization Service
		'WdiServiceHost', # Diagnostic Service Host
		'WdiSystemHost', # Diagnostic System Host
		'ALG', # Application Layer Gateway
		'PeerDistSvc', # BranchCache
		'Eaphost', # Extensible Authentication Protocol
		'fdPHost', # Function Discovery Provider Host
		'LxpSvc', # Language Experience Service
		'lltdsvc', # Link-Layer Topology Discovery Mapper
		'diagnosticshub.standardcollector.service', # Microsoft (R) Diagnostics Hub Standard Collector Service
		'MSiSCSI', # Microsoft iSCSI Initiator Service
		'WpcMonSvc', # WpcMonSvc
		'PNRPsvc', # Peer Name Resolution Protocol
		'p2psvc', # Peer Networking Grouping
		'p2pimsvc', # Peer Networking Identity Manager
		'PerfHost', # Performance Counter DLL Host
		'pla', # Performance Logs & Alerts
		'PNRPAutoReg', # PNRP Machine Name Publication
		'PrintNotify', # PrintNotify
		'wercplsupport', # Problem Reports & Solutions Control Panel
		'TroubleshootingSvc', # Recommended Troubleshooting Service
		'SessionEnv', # Remote Desktop Configuration
		'TermService', # Remote Desktop Service
		'UmRdpService', # Remote Desktop Services UserMode Port Redirector
		'RpcLocator', # Remote Procedure Call (RPC) Locator
		'RetailDemo', # Retail Demo Service
		'SCPolicySvc', # Smart Card Removal Policy
		'SNMPTRAP', # SNMP Trap
		'SharedRealitySvc', # Spatial Data Service
		'WiaRpc', # Still Image Acquisition Events
		'VacSvc', # Volumetric Audio Compositor Service
		'WalletService', # WalletService
		'wcncsvc', # Windows Connect Now
		'Wecsvc', # Windows Event Collector
		'perceptionsimulation', # Windows Perception Simulation Service
		'WinRM', # Windows Remote Management (WS-Management)
		'wmiApSrv', # WMI Performance Adapter
		'WwanSvc', # WWAN AutoConfig
		'XblAuthManager', # Xbox Live Auth Manager
		'XboxNetApiSvc', # Xbox Live Networking Service
		'RasAuto', # Remote Access Auto Connection Manager
		'XblGameSave', # Xbox Live Game Save
		'XboxGipSvc', # Xbox Accessory Management
		'PushToInstall', # Windows PushToInstall Service
		'spectrum', # Windows Perception Service
		'icssvc', # Windows Mobile Hotspot Service
		'wisvc', # Windows Insider Service
		'WerSvc', # Windows Error Reporting Service
		'FrameServer', # Windows Camera Frame Service
		'WFDSConMgrSvc', # Wi-Fi Direct Services Connection Manager Service
		'ScDeviceEnum', # Smart Card Device Enumeration Service
		'SCardSvr', # Smart Card
		'PhoneSvc', # Phone Service
		'IpxlatCfgSvc', # IP Translation Configuration Service
		'SharedAccess', # Internet Connection Sharing (ICS)
		'vmicvss', # Hyper-V Volume Shadow Copy Requestor
		'vmictimesync', # Hyper-V TIme Synchronization Service
		'vmicrdv', # Hyper-V Remote Desktop Virtualization Service
		'vmicvmsession', # Hyper-V PowerShell Direct Service
		'vmicheartbeat', # Hyper-V Heartbeat Service
		'vmicshutdown', # Hyper-V Guest Shudown Service
		'vmicguestinterface', # Hyper-V Guest Service Interface
		'vmickvpexchange', # Hyper-V Data Exchange Service
		'HvHost', # HV Host Service
		'FDResPub', # Function Discovery Resource Publication
		'diagsvc', # Diagnostic Execution Service
		'autotimesvc', # Cellular Time
		'bthserv', # Bluetooth Support Service
		'BTAGService', # Bluetooth Audio Gateway Service
		'AssignedAccessManagerSvc', # AssignedAccessManager Service
		'AJRouter', # AllJoyn Router Service
		'lfsvc', # Geolocation Service
		'CDPSvc', # Connected Devices Platform Service
		'DiagTrack', # Connected User Experiences and Telemetry
		'DPS', # Diagnostic Policy Service
		'iphlpsvc', # IP Helper
		'RasMan', # Remote Access Connection Manager
		'SstpSvc', # Secure Socket Tunneling Protocol Service
		'ShellHWDetection', # Shell Hardware Detection
		'SSDPSRV', # SSDP Discovery
		'WbioSrvc', # Windows Biometric Service
		'stisvc' # Windows Image Acquisition (WIA)
	Foreach ($Service in $Services) {
		Set-Service -Name $Service -StartupType 'Disabled'
		Stop-Service -Name $Service -Force
	}
	Write-Host 'Done.'
}

#################################################################
Write-Host 'Tweaking your sytem based on your tweaks...'
	Import-Module -Name '.\Tweaks.psm1'
	$Tweaks | ForEach {
		Invoke-Expression $_
	}

#################################################################
Write-Warning 'Ossify finished successfully. Would you like to restart now?'
	Set-Variable -Name 'UserResponse' -Value (Read-Host -Prompt '(Y/n)')
	Set-ExecutionPolicy restricted
	Stop-Transcript
	If (($UserResponse -eq 'Y') -or ($UserResponse -eq 'y')) {
		Restart-Computer -Confirm
	}
	Else {
		Write-Host 'Not restarting. Please restart device soon.'
	}
