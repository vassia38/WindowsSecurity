' Windows Configuration Audit Script
' Description: This script collects configuration data for security audit purposes from a Windows server,
' by generating traces on security-critical settings and grouping them into a native Windows archive (.cab).
' Minimum supported system: Windows Server 2008 R2

Option Explicit

Dim objFSO, objLogFile, shell
Dim strOutputFolder, strOutputLogFile

strOutputFolder = "C:\audit"


Set objFSO = CreateObject("Scripting.FilesystemObject")
Set shell = CreateObject("WScript.Shell")


Sub Init()
	If Not objFSO.FolderExists(strOutputFolder) Then
		objFSO.CreateFolder(strOutputFolder)
	End If
End sub


Sub Deinit()
	
	Dim cabFilePath, target, cmd, ddfFile
	cabFilePath = "C:\test\audit.cab"
	If objFSO.FileExists(cabFilePath) Then
		objFSO.DeleteFile(cabFilePath)
	End If
	set ddfFile = objFSO.CreateTextFile("C:\makecab.ddf", True)
	ddfFile.Writeline ".OPTION EXPLICIT"
	ddfFile.Writeline ".Set CabinetNameTemplate=audit.cab"
	ddfFile.Writeline ".Set DiskDirectoryTemplate=C:\"
	ddfFile.Writeline ".Set CompressionType=LZX"
	ddfFile.Writeline ".Set CompressionMemory=21"
	ddfFile.Writeline ".Set Cabinet=ON"
	ddfFile.Writeline ".Set DiskDirectory1=C:\"
	ddfFile.Writeline "C:\audit\servicesLog.txt"
	ddfFile.Writeline "C:\audit\processLog.txt"
	ddfFile.Writeline "C:\audit\networkLog.txt"
	ddfFile.Writeline "C:\audit\HotfixLog.txt"
	ddfFile.Writeline "C:\audit\UsersAndLocalGroupLog.txt"
	ddfFile.Writeline "C:\audit\UACLog.txt"
	ddfFile.Writeline "C:\audit\firewallLog.txt" 
	ddfFile.Writeline "C:\audit\SecurityPoliciesLog.txt"
	ddfFile.Writeline "C:\audit\CriticalSecurityEventsLog.txt ;"
	ddfFile.close
	
	cmd = "makecab /F C:\makecab.ddf"
	shell.Run cmd, 0, True
	
	WScript.Sleep 10000 
	
	objFSO.DeleteFolder strOutputFolder, True
	objFSO.DeleteFile "C:\makecab.ddf", True
	
	Set objFSO = Nothing
	Set shell = Nothing
End Sub

Sub LogMessage(message)
	message = " - " & message
	objLogFile.WriteLine message
End Sub


Sub Header()
	Dim hostName, colItems, wmi, objItem
	hostName = shell.ExpandEnvironmentStrings("%COMPUTERNAME%")
	LogMessage "Starting security events audit on " & hostName 
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	LogMessage "============= Windows Version ============="
	Set colItems = wmi.ExecQuery("SELECT * FROM Win32_OperatingSystem")
	For Each objItem in colItems
		LogMessage "" & objItem.Caption & " - " & objItem.Version
	Next
end Sub

Sub openFile(file)
	strOutputLogFile = file
	Set objLogFile = objFSO.OpenTextFile(strOutputFolder & "\" & strOutputLogFile, 8, True)
End Sub


Sub CollectServicesInfo()
	openFile "servicesLog.txt"
	logMessage Now
	Header()
	
	Dim colItems, objItem, wmi
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	LogMessage "============= Services ============="
	set colitems = wmi.ExecQuery("SELECT * FROM Win32_Service")
	For Each objItem in colItems
		LogMessage "Service: " & objItem.Name & " - Display Name: " & objItem.DisplayName & " - start mode: " & objItem.StartMode & " - state: " & objItem.State
	Next
	
	LogMessage "Audit completed"
	
	objLogFile.Close
End Sub


Sub CollectProcessInfo()
	
	openFile "processLog.txt"
	logMessage Now
	Header()	
	
	
	Dim colItems, objItem, wmi
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	
	LogMessage "============= Process ============="
	set colitems = wmi.ExecQuery("SELECT * FROM Win32_process")
	For Each objItem in colItems
		LogMessage "Process: " & objItem.Name & " Caption: " & objItem.Caption & " Process_ID: " & objItem.ProcessId & " [Memory Virtual Size :" & Round(objItem.VirtualSize / 1048576, 2) & "MB]" & " [Memory Physical Size: " & Round(objItem.WorkingSetSize / 1048576, 2) & "MB]"
	Next
	
	LogMessage "Audit completed"
	
	objLogFile.Close
End Sub


Sub CollectPhysicalNetworkInfo()
	
	openFile "networkLog.txt"
	logMessage Now
	Header()
	
	
	Dim colItems, objItem, wmi
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	
	LogMessage "============= Physical Network Information ============="
	set colitems = wmi.ExecQuery("SELECT * FROM Win32_Networkadapter")
	For Each objItem in colItems
		LogMessage "Network: " & objItem.Name & " manufacturer: " & objItem.Manufacturer & " Description: " & objItem.Description & " Adapter type :" & objItem.AdapterType & " Speed: " & objItem.MACAddress & " NetConnectionId: " & objItem.NetConnectionID
	Next

	LogMessage "============= Network Adapter Information ============="
	Set colItems = wmi.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")
	
	
	For Each objItem in colItems
		LogMessage "Description: " & objItem.Description
		LogMessage "DHCP Server: " & objItem.DHCPServer
		
		
		If IsArray(objItem.IPAddress) Then
			LogMessage "IP Address: " & Join(objItem.IPAddress, "; ")
		Else
			LogMessage "IP Address: Not available"
		End If
		
		
		If IsArray(objItem.IPSubnet) Then
			LogMessage "Subnet Mask: " & Join(objItem.IPSubnet, "; ")
		Else
			LogMessage "Subnet Mask: Not available"
		End If
		
		
		If IsArray(objItem.DefaultIPGateway) Then
			LogMessage "Default IP Gateway: " & Join(objItem.DefaultIPGateway, "; ")
		Else
			LogMessage "Default IP Gateway: Not available"
		End If
		
		
		If IsArray(objItem.DNSServerSearchOrder) Then
			LogMessage "DNS Server(s): " & Join(objItem.DNSServerSearchOrder, "; ")
		Else
			LogMessage "DNS Server(s): Not available"
		End If
		
		If objItem.DHCPEnabled Then
			LogMessage "DHCP Enabled: True"
		Else
			LogMessage "DHCP Enabled: False"
		End If
		
		
		LogMessage "MAC Address: " & objItem.MACAddress
		
		
		LogMessage "WINS Primary Server: " & objItem.WINSPrimaryServer
		LogMessage "WINS Secondary Server: " & objItem.WINSSecondaryServer
		LogMessage "------------------------------------------"
	Next
	
	LogMessage "Audit completed"
	objLogFile.Close
End Sub


Sub CollectHotfixInfo()
	
	openFile "HotfixLog.txt"
	logMessage Now
	Header()
	
	Dim colItems, objItem, wmi
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	LogMessage "============= Hotfix ============="
	Set colItems = wmi.ExecQuery("SELECT * FROM Win32_QuickFixEngineering")
	
	For Each objItem in colItems
		LogMessage "Computer Name: " & objItem.CSName
		LogMessage "Description: " & objItem.Description
		LogMessage "HotFix ID: " & objItem.HotFixID
		LogMessage "Installed By: " & objItem.InstalledBy
		LogMessage "Installed On: " & objItem.InstalledOn
		LogMessage "------------------------------------------"
	Next
	
	LogMessage "Audit completed"
	objLogFile.Close
End Sub


Sub CollectUsersAndLocalGroup()
	
	openFile "UsersAndLocalGroupLog.txt"
	logMessage Now
	Header()
	
	Dim colMembers, objMember, objGroup, colGroups, wmi, colUsers, objUser
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	
	LogMessage "============= Local Users ============="
	Set colUsers = wmi.ExecQuery("SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE")
		
	For Each objUser in colUsers
		
		LogMessage "=> User Name: " & objUser.Name
		
		LogMessage "   Domain: " & objUser.Domain
		
		LogMessage "   Status: " & objUser.Status
		
	Next
	
	LogMessage "============= Local Group ============="
	Set colGroups =  wmi.ExecQuery("SELECT * FROM Win32_Group WHERE LocalAccount = TRUE")
	
	For Each objGroup in colGroups
		LogMessage "Group: " & objGroup.Name & " (Domain: " & objGroup.Domain & ")"
		
		
		Set colMembers = wmi.ExecQuery("Associators of {Win32_Group.Domain='" & objGroup.Domain & "',Name='" & objGroup.Name & "'} WHERE AssocClass=Win32_GroupUser Role=GroupComponent")
		
		
		For Each objMember in colMembers
			LogMessage "  Member: " & objMember.Name & " (Domain: " & objMember.Domain & ")"
		Next
		
	Next
		
	LogMessage "------------------------------------------"
	
	LogMessage "Audit completed"
	objLogFile.Close
End Sub


Sub CollectUACInfo()
	
	openFile "UACLog.txt"
	logMessage Now
	Header()
	LogMessage "============= UAC Configuration ============="
	
	Dim UACRegPath, EnableLUA, ConsentPrompt, SecureDesktop 
	
	UACRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
	
	
	EnableLUA = shell.RegRead(UACRegPath & "EnableLUA")
	
	
	If EnableLUA = 1 Then
		
		LogMessage "[+] UAC is enabled."
		
		
	Else
		
		LogMessage "[-] UAC is disabled."
		
		
	End If
	
	
	
	
	
	On Error Resume Next
	
	
	ConsentPrompt = shell.RegRead(UACRegPath & "ConsentPromptBehaviorAdmin")
	
	
	If Err.Number <> 0 Then
		
		LogMessage "[!] Failed to read ConsentPromptBehaviorAdmin from registry."
		
		Err.Clear
	Else
		
		
		LogMessage "[?] ConsentPromptBehaviorAdmin value: " & ConsentPrompt
		
	End If
	
	
	
	SecureDesktop = shell.RegRead(UACRegPath & "PromptOnSecureDesktop")
	
	If Err.Number <> 0 Then
		
		LogMessage "[!] Failed to read PromptOnSecureDesktop from registry."
		
		Err.Clear
	Else
		
		LogMessage "[?] PromptOnSecureDesktop value: " & SecureDesktop
		
	End If
	
	
	
	
	LogMessage "[?] Analyzing UAC configuration level..."
	
	If EnableLUA = 0 Then
		
		LogMessage "[-] UAC is disabled, no further analysis required."
		
	Else
		If ConsentPrompt = 0 And SecureDesktop = 0 Then
			
			LogMessage "[+] UAC Level: Never Notify."
			
		ElseIf ConsentPrompt = 5 And SecureDesktop = 0 Then
			
			LogMessage "[+] UAC Level: Notify only when apps try to make changes (No secure desktop)."
			
		ElseIf ConsentPrompt = 5 And SecureDesktop = 1 Then
			
			LogMessage "[+] UAC Level: Notify only when apps try to make changes (Secure desktop enabled)."
			
		ElseIf ConsentPrompt = 2 And SecureDesktop = 1 Then
			
			LogMessage "[+] UAC Level: Always Notify with secure desktop."
			
		Else
			
			LogMessage "[!] Unknown UAC configuration."
			
		End If
		
	End If
	
	LogMessage "Audit completed"
	objLogFile.Close
End Sub


Function ConvertProfileType(profileType)
	Select Case profileType
	Case 1
		ConvertProfileType = "Domain"
	Case 2
		ConvertProfileType = "Private"
	Case 4
		ConvertProfileType = "Public"
	Case Else
		ConvertProfileType = "Unknown"
	End Select
End Function

Function SafeIIf(condition, truePart, falsePart)
	If condition Then
		SafeIIf = truePart
	Else
		SafeIIf = falsePart
	End If
End Function


Sub CollectFirewallInfo()
	
	openFile "firewallLog.txt"
	logMessage Now
	Header()
	
	
	Dim objFirewall, activeProfiles, profileType, fwEnabled, blockAllInbound, defaultInboundAction, defaultOutboundAction, iff, rules, ruleCount, ruleIndex, objRule
	LogMessage "============= Firewall Configuration ============="
	
	Set objFirewall = CreateObject("HNetCfg.FwPolicy2")
	activeProfiles = objFirewall.CurrentProfileTypes
	
	For Each profileType In Array(1, 2, 4)
		If (activeProfiles And profileType) Then
			LogMessage "[+] Active Profile: " & ConvertProfileType(profileType)
			
			
			fwEnabled = objFirewall.FirewallEnabled(profileType)
			LogMessage "    Firewall Enabled: " & fwEnabled
			
			
			blockAllInbound = objFirewall.BlockAllInboundTraffic(profileType)
			LogMessage "    Block All Inbound Traffic: " & blockAllInbound
			
			
			defaultInboundAction = objFirewall.DefaultInboundAction(profileType)
			iff = SafeIIf(defaultInboundAction = 0, "Allow", "Block")
			LogMessage "    Default Inbound Action: " & iff
			
			
			defaultOutboundAction = objFirewall.DefaultOutboundAction(profileType)
			iff = SafeIIf(defaultOutboundAction = 0, "Allow", "Block")
			LogMessage "    Default Outbound Action: " & iff
			
			LogMessage "-------------------------------------------"
		End If
	Next
	
	
	LogMessage "============= Firewall rules ============="
	
	Set rules = objFirewall.Rules
	
	
	For each objRule In rules
		
		Dim action, direction, protocol, profile, localPorts, applicationName, profiles
		action = SafeIIf(objRule.Action = 1, "Allow", "Block")
		direction = SafeIIf(objRule.Direction = 1, "Inbound", "Outbound")
		protocol = SafeIIf(objRule.Protocol = 6, "TCP", "UDP") 
		localPorts = objRule.LocalPorts
		profiles = objRule.Profiles
		applicationName = objRule.ApplicationName
		
		If (profiles And 1) Then profile = "Domain"
		If (profiles And 2) Then profile = "Private"
		If (profiles And 4) Then profile = "Public"
		
		LogMessage "Name: " & objRule.Name
		LogMessage "Action: " & action
		LogMessage "Direction: " & direction
		LogMessage "Protocol: " & protocol
		LogMessage "Local Ports: " & localPorts
		LogMessage "Profiles: " & profile
		LogMessage "Application: " & applicationName
		LogMessage "----------------------------------------"
	Next

	LogMessage "Audit completed"
	objLogFile.Close
End Sub


Sub CollectSecurityPolicies()
	
	openFile "SecurityPoliciesLog.txt"
	logMessage Now
	Header()
	LogMessage "============= Security password and account policies ============="
	
	LogMessage "Starting password and account policies audit .."
	
	Dim commandOutput
	
	commandOutput = shell.Exec("net accounts").StdOut.ReadAll
	
	LogMessage commandOutput
	
	LogMessage "Audit completed"
	objLogFile.Close	
End Sub


Sub CollectCriticalSecurityEvents()
	
	openFile "CriticalSecurityEventsLog.txt"
	logMessage Now
	Header()
	
	Dim wmi, colEvents, objEvent
	Set wmi = GetObject("winmgmts:\\.\root\cimv2")
	
	Set colEvents = wmi.ExecQuery("SELECT * FROM Win32_NTLogEvent WHERE Logfile = 'Security'")
	
	LogMessage "============= Critical Security Events ============="
	
	For Each objEvent In colEvents
		LogMessage "------------------------------------------"
		LogMessage "Event ID: " & objEvent.EventCode
		LogMessage "Source: " & objEvent.SourceName
		LogMessage "Category: " & objEvent.Category
		If IsArray(objEvent.InsertionStrings) Then
			LogMessage "Description: "
			Dim i, insertionString
			For i = LBound(objEvent.InsertionStrings) To UBound(objEvent.InsertionStrings)
				insertionString = objEvent.InsertionStrings(i)
				LogMessage "  - " & insertionString
			Next
		Else
			LogMessage "Description: " & objEvent.InsertionStrings
		End If
		
		LogMessage "Time Generated: " & objEvent.TimeGenerated
		LogMessage "User: " & objEvent.User
		LogMessage "Computer Name: " & objEvent.ComputerName
		LogMessage "------------------------------------------"
	Next
	
	LogMessage "Audit completed"
	objLogFile.Close
End Sub


Call Init()
Call CollectServicesInfo()
Call CollectProcessInfo()
Call CollectPhysicalNetworkInfo()
Call CollectHotfixInfo()
Call CollectUsersAndLocalGroup()
Call CollectUACInfo()
Call CollectFirewallInfo()
Call CollectSecurityPolicies()
Call CollectCriticalSecurityEvents()
Call Deinit()


