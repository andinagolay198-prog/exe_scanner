/*
  EXE Scanner v3 - Advanced RAT & C2 Detection Rules
  Covers: AsyncRAT, njRAT, QuasarRAT, Cobalt Strike, Remcos, DarkComet
*/

rule AsyncRAT_Client {
    meta:
        description = "AsyncRAT remote access trojan client"
        severity = "CRITICAL"
        category = "rat"
        family = "AsyncRAT"
    strings:
        $s1 = "AsyncRAT" ascii wide nocase
        $cfg1 = "Ports" ascii wide
        $cfg2 = "Hosts" ascii wide
        $cfg3 = "Version" ascii wide
        $cfg4 = "Install" ascii wide
        $net1 = "sock" ascii wide
        $net2 = "GetHostAddresses" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or (all of ($cfg*) and 2 of ($net*)))
}

rule njRAT_Generic {
    meta:
        description = "njRAT (Bladabindi) remote access trojan"
        severity = "CRITICAL"
        category = "rat"
        family = "njRAT"
    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "Bladabindi" ascii wide nocase
        $s3 = "lv_host" ascii wide
        $s4 = "lv_port" ascii wide
        $cmd1 = "kl" ascii wide
        $cmd2 = "proc" ascii wide
        $cmd3 = "rn" ascii wide
        $cmd4 = "CAP" ascii wide
        $cmd5 = "PLG" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or $s2 or ($s3 and $s4) or (3 of ($cmd*)))
}

rule QuasarRAT_Generic {
    meta:
        description = "QuasarRAT remote access trojan"
        severity = "CRITICAL"
        category = "rat"
        family = "QuasarRAT"
    strings:
        $s1 = "Quasar" ascii wide
        $s2 = "xRAT" ascii wide
        $s3 = "DoUploadAndExecute" ascii wide
        $s4 = "DoShellExecute" ascii wide
        $s5 = "GetProcesses" ascii wide
        $s6 = "GetDesktop" ascii wide
        $proto = "INITIALIZE" ascii wide
        $proto2 = "STATUS_ONLINE" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or $s2 or (2 of ($s3,$s4,$s5,$s6)) or ($proto and $proto2))
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon or stager"
        severity = "CRITICAL"
        category = "apt"
        family = "CobaltStrike"
    strings:
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "beacon.dll" ascii wide nocase
        $s3 = "%s (admin)" ascii wide
        $s4 = "Failed to open process token" ascii wide
        $s5 = "could not find the function in" ascii wide
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $ua = "Mozilla/5.0 (compatible; MSIE " ascii wide
        $magic = { FC E8 ?? ?? ?? ?? 60 89 E5 31 D2 64 8B }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) or any of ($pipe*) or $magic or ($ua and $s1))
}

rule Remcos_RAT {
    meta:
        description = "Remcos Remote Control & Surveillance"
        severity = "CRITICAL"
        category = "rat"
        family = "Remcos"
    strings:
        $s1 = "Remcos" ascii wide nocase
        $s2 = "Breaking-Security" ascii wide nocase
        $s3 = "remcos_mutex" ascii wide nocase
        $s4 = "REMCOS_" ascii wide
        $cmd1 = "kCapture" ascii wide nocase
        $cmd2 = "kKeyLog" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or $s2 or $s3 or $s4 or (any of ($cmd*)))
}

rule DarkComet_RAT {
    meta:
        description = "DarkComet remote access trojan"
        severity = "CRITICAL"
        category = "rat"
        family = "DarkComet"
    strings:
        $s1 = "DarkComet" ascii wide nocase
        $s2 = "DARKCOMET" ascii wide
        $s3 = "DarkComet-RAT" ascii wide
        $s4 = "dc3_uninstall" ascii wide
        $s5 = "HVNC_" ascii wide
        $mutex = "DC_MUTEX-" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or $mutex)
}

rule NanoCore_RAT {
    meta:
        description = "NanoCore remote access trojan"
        severity = "CRITICAL"
        category = "rat"
        family = "NanoCore"
    strings:
        $s1 = "NanoCore" ascii wide
        $s2 = "Client.dll" ascii wide
        $s3 = "CoreServiceLib" ascii wide
        $s4 = "PluginCommand" ascii wide
        $s5 = "PacketReader" ascii wide
        $s6 = "PacketWriter" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or (2 of ($s2,$s3,$s4,$s5,$s6)))
}

rule Generic_Keylogger {
    meta:
        description = "Generic keylogger indicators"
        severity = "HIGH"
        category = "stealer"
        family = "Keylogger"
    strings:
        $s1 = "SetWindowsHookEx" ascii
        $s2 = "GetAsyncKeyState" ascii
        $s3 = "keylog" ascii wide nocase
        $s4 = "keystroke" ascii wide nocase
        $s5 = "keyboard" ascii wide nocase
        $s6 = "clipboard" ascii wide nocase
        $smtp = "smtp.gmail.com" ascii wide nocase
        $smtp2 = "mail.send" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (($s1 and $s2) or (2 of ($s3,$s4,$s5,$s6) and ($smtp or $smtp2)))
}

rule Shellcode_Loader_Generic {
    meta:
        description = "Generic shellcode loader / stager"
        severity = "HIGH"
        category = "loader"
        family = "Loader"
    strings:
        $b1 = { FC E8 ?? 00 00 00 }       // common shellcode prologue
        $b2 = { 60 89 E5 31 D2 64 8B 52 } // PEB walk
        $b3 = { 4D 5A 90 00 03 00 00 00 } // MZ in data (embedded PE)
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "LoadLibraryA" ascii
        $api5 = "GetProcAddress" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($b1 or $b2) or $b3 or (3 of ($api*)))
}
