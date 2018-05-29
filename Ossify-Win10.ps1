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

#Prevents 'Suggested Applications' from returning
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" "DisableWindowsConsumerFeatures" 1
