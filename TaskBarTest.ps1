#Load the XML
$StartLayoutPath = "C:\BSS\Student.xml"
$LoggedInUser = $(Get-WMIObject -class Win32_ComputerSystem -Property UserName).UserName
Import-StartLayout -LayoutPath $StartLayoutPath -MountPath 'C:\'
#Having issues with line above, doesn't recognise as cmdlet, believe it requires elevate privl?

#Edit the registry
#HKU is incorrect path to HKEY_USERS will re-evaluate 
#New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
#$regKey = HKU:\$Usersid\HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer
#New-Item -Path HKEY_USERS:\$Usersid\HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer
#New-ItemProperty -path HKEY_USERS:\$Usersid\HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Type Dword -Value 1 -Force
#New-ItemProperty -path HKEY_USERS:\$Usersid\HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Type ExpandString -Value $StartLayoutPath -Force

New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer
New-ItemProperty -path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name LockedStartLayout -Type Dword -Value 1 -Force
New-ItemProperty -path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name StartLayoutFile -Type ExpandString -Value $StartLayoutPath -Force



#Restart Explorer 
Stop-Process -ProcessName explorer
Start-Sleep -s 10


#Im not sure deleting the keys is required
#sleep is to let explorer finish restart b4 deleting reg keys
#Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Force
#Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Force
#Stop-Process -ProcessName explorer