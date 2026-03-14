rule CrackTool_Keygen {
    meta:
        description = "Key generator tool — tạo license key giả"
        severity    = "CRITICAL"
        category    = "crack"
        family      = "keygen"
    strings:
        $k1 = "keygen"         ascii wide nocase
        $k2 = "key generator"  ascii wide nocase
        $k3 = "serial number"  ascii wide nocase
        $k4 = "generate key"   ascii wide nocase
        $k5 = "crack by"       ascii wide nocase
        $k6 = "cracked by"     ascii wide nocase
        $k7 = "patched by"     ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of ($k*)
}

rule CrackTool_Patcher {
    meta:
        description = "Binary patcher — patch executable để bypass"
        severity    = "CRITICAL"
        category    = "crack"
        family      = "patcher"
    strings:
        $p1 = "backup" nocase ascii wide
        $p2 = ".bak"   ascii wide
        $p3 = "patch"  nocase ascii wide
        $p4 = "WriteProcessMemory" ascii
        $p5 = "VirtualProtect"     ascii
    condition:
        uint16(0) == 0x5A4D and
        ($p4 and $p5) and ($p1 or $p2 or $p3)
}

rule CrackTool_Loader_Rsrc {
    meta:
        description = "Loader nhúng payload trong resource section lớn"
        severity    = "HIGH"
        category    = "crack"
        family      = "loader"
    strings:
        $la = "LoadResource"     ascii
        $lb = "FindResource"     ascii
        $lc = "SizeofResource"   ascii
        $ld = "LockResource"     ascii
        $le = "VirtualAlloc"     ascii
        $lf = "VirtualProtect"   ascii
    condition:
        uint16(0) == 0x5A4D and
        3 of ($la, $lb, $lc, $ld) and
        1 of ($le, $lf)
}

rule CrackTool_AntiDebug_Combined {
    meta:
        description = "Tool kết hợp nhiều kỹ thuật anti-debug / anti-analysis"
        severity    = "HIGH"
        category    = "evasion"
        family      = "anti_debug"
    strings:
        $d1 = "IsDebuggerPresent"           ascii
        $d2 = "CheckRemoteDebuggerPresent"  ascii
        $d3 = "NtQueryInformationProcess"   ascii
        $d4 = "OutputDebugStringA"          ascii
        $v1 = "VBOX" nocase ascii wide
        $v2 = "VMware" nocase ascii wide
        $v3 = "QEMU"  nocase ascii wide
        $v4 = "Sandboxie" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($d*)) or
        (1 of ($d*) and 1 of ($v*))
}

rule CrackTool_DirectSyscall {
    meta:
        description = "Dùng direct syscall để bypass API hooks của AV/EDR"
        severity    = "HIGH"
        category    = "evasion"
        family      = "syscall_bypass"
    strings:
        $s1 = { 4C 8B D1 B8 ?? 00 00 00 0F 05 }  // NtAllocateVirtualMemory syscall stub
        $s2 = { 4C 8B D1 B8 ?? 00 00 00 0F 05 }  // generic syscall stub
        $s3 = "NtAllocateVirtualMemory" ascii
        $s4 = "NtWriteVirtualMemory"    ascii
        $s5 = "NtCreateThreadEx"        ascii
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or $s2) and any of ($s3, $s4, $s5)
}

rule CrackTool_PyInstaller_Crack {
    meta:
        description = "Crack tool được đóng gói bằng PyInstaller"
        severity    = "HIGH"
        category    = "packer"
        family      = "pyinstaller"
    strings:
        $p1 = "pyiboot01"    ascii
        $p2 = "_MEIPASS"     ascii
        $p3 = "pyi-windows"  ascii
        $k1 = "keygen"       nocase ascii wide
        $k2 = "crack"        nocase ascii wide
        $k3 = "patch"        nocase ascii wide
        $k4 = "bypass"       nocase ascii wide
        $k5 = "license"      nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and
        any of ($p*) and any of ($k*)
}

rule CrackTool_GoLang_Crack {
    meta:
        description = "Crack tool viết bằng Go (không có Rich Header)"
        severity    = "HIGH"
        category    = "crack"
        family      = "golang_crack"
    strings:
        $g1 = "Go build ID" ascii
        $g2 = "runtime.main" ascii
        $g3 = "goroutine"  ascii
        $k1 = "keygen"  nocase ascii wide
        $k2 = "crack"   nocase ascii wide
        $k3 = "bypass"  nocase ascii wide
        $k4 = "license" nocase ascii wide
        $k5 = "patch"   nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and
        any of ($g*) and any of ($k*)
}
