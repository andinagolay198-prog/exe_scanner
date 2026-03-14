import "pe"

/*
    YARA Rules: Persistence, Ransomware, Anti-Analysis Techniques
*/

// ===== PERSISTENCE =====

rule Persistence_Registry_Autorun {
    meta:
        description = "Malware adding itself to registry autorun keys"
        severity = "HIGH"
        category = "persistence"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"            ascii wide nocase
        $r2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"        ascii wide nocase
        $r3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"    ascii wide nocase
        $r4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase
        $r5 = "SYSTEM\\CurrentControlSet\\Services"                          ascii wide nocase
        $api1 = "RegSetValueEx"     ascii wide
        $api2 = "RegCreateKeyEx"    ascii wide
        $api3 = "RegOpenKeyEx"      ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($r*)) and
        (1 of ($api*))
}

rule Persistence_Scheduled_Task {
    meta:
        description = "Malware creating scheduled tasks for persistence"
        severity = "HIGH"
        category = "persistence"
    strings:
        $t1 = "schtasks"            ascii wide nocase
        $t2 = "ITaskScheduler"      ascii wide
        $t3 = "ITaskService"        ascii wide
        $t4 = "Schedule.Service"    ascii wide
        $t5 = "TaskScheduler"       ascii wide
        $t6 = "/create"             ascii wide nocase
        $t7 = "/sc onlogon"         ascii wide nocase
        $t8 = "/sc onstart"         ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (($t1 and ($t6 or $t7 or $t8)) or
         (2 of ($t2,$t3,$t4,$t5)))
}

rule Persistence_Service_Install {
    meta:
        description = "Malware installing itself as a Windows Service"
        severity = "HIGH"
        category = "persistence"
    strings:
        $s1 = "CreateService"       ascii wide
        $s2 = "OpenSCManager"       ascii wide
        $s5 = "SERVICE_AUTO_START"  ascii wide
        $s6 = "SERVICE_BOOT_START"  ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($s1 and $s2) and
        (1 of ($s5,$s6))
}

rule Persistence_COM_Hijacking {
    meta:
        description = "COM object hijacking for persistence and privilege escalation"
        severity = "HIGH"
        category = "persistence,privesc"
    strings:
        $c1 = "HKCU\\Software\\Classes\\CLSID\\" ascii wide nocase
        $c2 = "InprocServer32"                    ascii wide
        $c3 = "CoCreateInstance"                  ascii wide
        $c4 = "CoRegisterClassObject"             ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($c1 and $c2) or
        ($c3 and $c4)
}

// ===== RANSOMWARE =====

rule Ransomware_File_Encryption {
    meta:
        description = "Ransomware file encryption behavior"
        severity = "CRITICAL"
        category = "ransomware"
    strings:
        $e1 = "CryptEncrypt"        ascii wide
        $e2 = "CryptGenKey"         ascii wide
        $e3 = "BCryptEncrypt"       ascii wide
        $e4 = "BCryptGenerateSymmetricKey" ascii wide
        // File operations in bulk
        $f1 = "FindFirstFile"       ascii wide
        $f2 = "FindNextFile"        ascii wide
        $f3 = "WriteFile"           ascii wide
        // Ransom note
        $n1 = "YOUR FILES"          ascii wide nocase
        $n2 = "DECRYPT"             ascii wide nocase
        $n3 = "BITCOIN"             ascii wide nocase
        $n4 = "WALLET"              ascii wide nocase
        $n5 = "HOW TO RECOVER"      ascii wide nocase
        $n6 = "RANSOM"              ascii wide nocase
        $n7 = ".LOCKED"             ascii wide nocase
        $n8 = ".encrypted"          ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($e*)) and
        ($f1 and $f2 and $f3) and
        (2 of ($n*))
}

rule Ransomware_Shadow_Delete {
    meta:
        description = "Ransomware deleting shadow copies to prevent recovery"
        severity = "CRITICAL"
        category = "ransomware"
    strings:
        $vss1 = "vssadmin"              ascii wide nocase
        $vss2 = "delete shadows"        ascii wide nocase
        $vss3 = "Win32_ShadowCopy"      ascii wide nocase
        $vss4 = "WBEM\\WMI"            ascii wide nocase
        $vss5 = "bcdedit"               ascii wide nocase
        $vss6 = "/set {default} recoveryenabled no" ascii wide nocase
        $vss7 = "wmic shadowcopy delete" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($vss*))
}

// ===== ANTI-ANALYSIS =====

rule AntiAnalysis_Debugger_Detect {
    meta:
        description = "Multiple anti-debugging techniques combined"
        severity = "MEDIUM"
        category = "anti_analysis"
    strings:
        $d1 = "IsDebuggerPresent"               ascii wide
        $d2 = "CheckRemoteDebuggerPresent"       ascii wide
        $d3 = "NtQueryInformationProcess"        ascii wide
        $d4 = "OutputDebugString"                ascii wide
        $d5 = "FindWindow"                       ascii wide
        $d6 = "NtSetInformationThread"           ascii wide  // hide from debugger
        $d7 = "CloseHandle"                      ascii wide
        // Debugger window names
        $w1 = "OllyDbg"                         ascii wide nocase
        $w2 = "x64dbg"                          ascii wide nocase
        $w3 = "IDA Pro"                         ascii wide nocase
        $w4 = "WinDbg"                          ascii wide nocase
        $w5 = "Immunity Debugger"               ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($d*)) or
        (1 of ($d*) and 1 of ($w*))
}

rule AntiAnalysis_VM_Detection {
    meta:
        description = "Virtual machine / sandbox detection"
        severity = "MEDIUM"
        category = "anti_analysis,anti_sandbox"
    strings:
        // VMware strings
        $vm1 = "VMware"             ascii wide nocase
        $vm2 = "VBOX"               ascii wide nocase
        $vm3 = "VirtualBox"         ascii wide nocase
        $vm4 = "VIRTUAL"            ascii wide nocase
        // VM-specific registry
        $r1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" ascii wide nocase
        $r2 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii wide nocase
        $r3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii wide nocase
        // CPUID vendor check
        $cpu1 = "VMwareVMware"      ascii
        $cpu2 = "KVMKVMKVM"         ascii
        $cpu3 = "XenVMMXenVMM"      ascii
        // Timing
        $t1 = "GetTickCount"        ascii wide
        $t2 = "QueryPerformanceCounter" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($vm*) or 1 of ($r*) or 1 of ($cpu*)) and
        (1 of ($t*))
}

rule AntiAnalysis_Self_Delete {
    meta:
        description = "Malware deleting itself after execution"
        severity = "HIGH"
        category = "anti_analysis,evasion"
    strings:
        $sd1 = "DeleteFile"             ascii wide
        $sd2 = "MoveFileEx"             ascii wide
        $sd3 = "cmd /c del"             ascii wide nocase
        $sd4 = "cmd.exe /c del"         ascii wide nocase
        $own1 = "GetModuleFileName"     ascii wide
        $own2 = "GetModuleHandleEx"     ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (($sd1 or $sd2) and ($own1 or $own2)) or
        ($sd3 or $sd4)
}

rule AntiAnalysis_Encrypted_Config {
    meta:
        description = "Malware with encrypted/obfuscated configuration"
        severity = "HIGH"
        category = "anti_analysis,obfuscation"
    strings:
        $c1 = "CryptDecrypt"        ascii wide
        $c2 = "BCryptDecrypt"       ascii wide
        $c3 = "RC4"                 ascii wide
        $c4 = "AES"                 ascii wide
        $c5 = "CryptImportKey"      ascii wide
        // Config loading patterns
        $l1 = "FindResource"        ascii wide
        $l2 = "LoadResource"        ascii wide
        $l3 = "LockResource"        ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($c*)) and
        (2 of ($l*))
}

rule AntiAnalysis_Code_Obfuscation {
    meta:
        description = "Heavy code obfuscation (NOP sleds, junk code, encrypted blocks)"
        severity = "MEDIUM"
        category = "anti_analysis,obfuscation"
    condition:
        uint16(0) == 0x5A4D and
        pe.entry_point >= pe.sections[1].virtual_address
}
