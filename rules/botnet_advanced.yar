import "pe"

/*
    YARA Rules: P2P Botnet, Stealth & Advanced Hidden Techniques
*/

// ===== P2P BOTNET =====

rule Botnet_P2P_Kademlia {
    meta:
        description = "P2P botnet using Kademlia DHT protocol (like Storm/Waledac)"
        severity = "CRITICAL"
        category = "botnet,p2p"
    strings:
        $k1 = "kademlia"        ascii wide nocase
        $k2 = "DHT"             ascii wide
        $k3 = "bootstrap"       ascii wide nocase
        $k4 = "node_id"         ascii wide nocase
        $k5 = "peer_list"       ascii wide nocase
        $k6 = "FIND_NODE"       ascii wide
        $k7 = "STORE"           ascii wide
        $udp = "sendto"         ascii wide
        $dns = "gethostbyname"  ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($k*)) and ($udp or $dns)
}

rule Botnet_P2P_Custom_Protocol {
    meta:
        description = "Custom P2P protocol botnet - encrypted peer communication"
        severity = "HIGH"
        category = "botnet,p2p,encrypted"
    strings:
        // Peer discovery
        $p1 = "peer_list"       ascii wide nocase
        $p2 = "node_list"       ascii wide nocase
        $p3 = "peer_connect"    ascii wide nocase
        // Encryption
        $e1 = "RC4"             ascii wide nocase
        $e2 = "AES"             ascii wide nocase
        $e3 = "CryptEncrypt"    ascii wide
        // Network
        $n1 = "WSAStartup"      ascii wide
        $n2 = "bind"            ascii wide
        $n3 = "listen"          ascii wide
        $n4 = "accept"          ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($p*)) and (1 of ($e*)) and
        ($n1) and (2 of ($n2,$n3,$n4))
}

rule Botnet_Necurs_P2P {
    meta:
        description = "Necurs-style P2P botnet with rootkit component"
        severity = "CRITICAL"
        category = "botnet,p2p,rootkit"
        family = "Necurs"
    strings:
        $n1 = "necurs"          ascii wide nocase
        $n2 = "r2p2"            ascii wide nocase
        // Driver/kernel references
        $d1 = "\\\\.\\pipe\\"   ascii wide
        $d2 = "NtLoadDriver"    ascii wide
        $d3 = "ZwSetSystemInformation" ascii wide
        $d4 = "\\\\.\\Global\\" ascii wide
        // P2P
        $p1 = "peer"            ascii wide nocase
        $p2 = "bootstrap"       ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($n*) or
         (2 of ($d*) and 1 of ($p*)))
}

// ===== STEALTH & EVASION =====

rule Stealth_Process_Hollowing {
    meta:
        description = "Process Hollowing / RunPE technique"
        severity = "CRITICAL"
        category = "evasion,injection"
    strings:
        $ph1 = "NtUnmapViewOfSection"   ascii wide
        $ph2 = "ZwUnmapViewOfSection"   ascii wide
        $ph3 = "VirtualAllocEx"         ascii wide
        $ph4 = "WriteProcessMemory"     ascii wide
        $ph5 = "SetThreadContext"       ascii wide
        $ph6 = "ResumeThread"           ascii wide
        $ph7 = "CreateProcessA"         ascii wide
        $ph8 = "CREATE_SUSPENDED"       ascii wide nocase
        $flag = { 04 00 00 00 }         // CREATE_SUSPENDED flag value
    condition:
        uint16(0) == 0x5A4D and
        (($ph1 or $ph2) and $ph3 and $ph4 and $ph5 and ($ph6 or $ph7) and ($ph8 or $flag))
}

rule Stealth_DLL_Injection_Reflective {
    meta:
        description = "Reflective DLL Injection - loads DLL from memory without disk"
        severity = "CRITICAL"
        category = "evasion,injection"
    strings:
        $r1 = "ReflectiveDLLInject"     ascii wide
        $r2 = "ReflectiveLoader"        ascii wide
        $r3 = "LoadRemoteLibraryR"      ascii wide
        // Signatures of reflective loader stub
        $stub = { 55 8B EC 83 EC ?? 53 56 57 }  // common prolog
        // Manual PE mapping
        $m1 = "VirtualAlloc"            ascii wide
        $m2 = "GetProcAddress"          ascii wide
        $m3 = "LoadLibraryA"            ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($r*) or $stub or
         ($m1 and $m2 and $m3 and
          not (pe.imports("kernel32.dll","LoadLibraryA"))))
}

rule Stealth_DKOM_Rootkit {
    meta:
        description = "DKOM (Direct Kernel Object Manipulation) rootkit techniques"
        severity = "CRITICAL"
        category = "rootkit,kernel"
    strings:
        // Kernel object manipulation
        $k1 = "ZwQuerySystemInformation"    ascii wide
        $k2 = "NtQuerySystemInformation"    ascii wide
        $k3 = "PsGetProcessId"              ascii wide
        $k4 = "PsLookupProcessByProcessId"  ascii wide
        // SSDT hooking
        $s1 = "KeServiceDescriptorTable"    ascii wide
        $s2 = "ZwOpenProcess"               ascii wide
        // Driver loading
        $d1 = "NtLoadDriver"                ascii wide
        $d2 = "ZwLoadDriver"                ascii wide
        $d3 = "ObReferenceObjectByName"     ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($k*) and 1 of ($s*)) or
        (1 of ($d*) and 2 of ($k*))
}

rule Stealth_TLS_Callback_Exec {
    meta:
        description = "Code runs via TLS callbacks before entry point - anti-debug"
        severity = "HIGH"
        category = "evasion,anti_analysis"
    strings:
        $tls = ".tls"                   ascii
        $anti1 = "IsDebuggerPresent"    ascii wide
        $anti2 = "CheckRemoteDebuggerPresent" ascii wide
        $anti3 = "NtQueryInformationProcess" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($tls) and (1 of ($anti*)) and
        pe.data_directories[9].virtual_address != 0  // TLS directory exists
}

rule Stealth_Timing_AntiSandbox {
    meta:
        description = "Timing-based sandbox evasion - sleeps long time or checks timing"
        severity = "MEDIUM"
        category = "evasion,anti_sandbox"
    strings:
        $t1 = "GetTickCount"            ascii wide
        $t2 = "QueryPerformanceCounter" ascii wide
        $t3 = "timeGetTime"             ascii wide
        $t4 = "GetSystemTimeAsFileTime" ascii wide
        $sleep = "Sleep"                ascii wide
        $ntsleep = "NtDelayExecution"   ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($sleep or $ntsleep) and
        (2 of ($t*))
}

rule Stealth_Phantom_Hollowing {
    meta:
        description = "Transacted Hollowing / Phantom DLL - advanced process hiding"
        severity = "CRITICAL"
        category = "evasion,injection,advanced"
    strings:
        $h1 = "NtCreateTransaction"         ascii wide
        $h2 = "NtCreateSection"             ascii wide
        $h3 = "NtMapViewOfSection"          ascii wide
        $h4 = "NtCreateProcessEx"           ascii wide
        $h5 = "ZwCreateProcessEx"           ascii wide
        $h6 = "NtCreateTransactionManager"  ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($h1 and $h2 and $h3) or
        ($h4 and $h2 and $h3) or
        ($h6 and $h1) or ($h5 and $h1)
}

rule Stealth_Heaven_Gate {
    meta:
        description = "Heaven's Gate - 32-bit process executing 64-bit code to bypass hooks"
        severity = "CRITICAL"
        category = "evasion,advanced"
    strings:
        // Far jump to 64-bit code segment (0x33 selector)
        $hg1 = { EA ?? ?? ?? ?? 33 00 }   // far jmp xx:0033
        $hg2 = { FF 2D ?? ?? ?? ?? }       // jmp far [mem]
        // Wow64 related
        $w1 = "Wow64Transition"         ascii wide
        $w2 = "ntdll_wow64"             ascii wide
        $w3 = "wow64cpu.dll"            ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($hg*) or 2 of ($w*))
}

// ===== ADVANCED HIDDEN C2 =====

rule Botnet_C2_DNS_Tunneling {
    meta:
        description = "DNS tunneling for covert C2 communication"
        severity = "CRITICAL"
        category = "botnet,c2,covert"
    strings:
        $dns1 = "DnsQuery"          ascii wide
        $dns2 = "DnsQueryEx"        ascii wide
        $dns3 = "gethostbyname"     ascii wide
        // DNS record types used for tunneling
        $txt  = "TXT"               ascii wide
        $null_record = "NULL"       ascii wide
        $mx   = "MX"                ascii wide
        // Encoding
        $enc1 = "base32"            ascii wide nocase
        $enc2 = "base64"            ascii wide nocase
        $enc3 = "hex"               ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($dns*)) and
        (1 of ($txt, $null_record, $mx)) and
        (1 of ($enc*))
}

rule Botnet_C2_Steganography {
    meta:
        description = "C2 communication hidden in image/media files (steganography)"
        severity = "CRITICAL"
        category = "botnet,c2,steganography"
    strings:
        // Image format parsing
        $img1 = "PNG"                   ascii
        $img2 = { 89 50 4E 47 }         // PNG magic
        $img3 = { FF D8 FF }            // JPEG magic
        $img4 = "BMP"                   ascii
        // Download + parse
        $dl   = "URLDownloadToFile"     ascii wide
        $http = "WinHttpOpen"           ascii wide
        // Bit manipulation (LSB steganography)
        $bit1 = "BitBlt"                ascii wide
        $bit2 = "GetDIBits"             ascii wide
        $bit3 = "SetDIBits"             ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($dl or $http) and
        (1 of ($img*)) and
        (1 of ($bit*))
}

rule Botnet_C2_Social_Media {
    meta:
        description = "Botnet using social media (Twitter/Telegram/GitHub) as C2"
        severity = "HIGH"
        category = "botnet,c2,covert"
    strings:
        $tw1 = "twitter.com"            ascii wide nocase
        $tw2 = "api.twitter.com"        ascii wide nocase
        $tg1 = "api.telegram.org"       ascii wide nocase
        $tg2 = "t.me/"                  ascii wide nocase
        $gh1 = "api.github.com"         ascii wide nocase
        $gh2 = "raw.githubusercontent"  ascii wide nocase
        $dc1 = "discordapp.com"         ascii wide nocase
        $dc2 = "discord.com/api"        ascii wide nocase
        $pastebin = "pastebin.com"      ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($tw*) or 1 of ($tg*) or
         1 of ($gh*) or 1 of ($dc*) or $pastebin)
}

rule Botnet_Tor_Hidden_Service {
    meta:
        description = "Bot connecting to Tor .onion C2 hidden service"
        severity = "CRITICAL"
        category = "botnet,c2,anonymous"
    strings:
        $tor1 = ".onion"            ascii wide nocase
        $tor2 = "127.0.0.1:9050"    ascii wide
        $tor3 = "127.0.0.1:9150"    ascii wide
        $tor4 = "socks5"            ascii wide nocase
        $tor5 = "TorProxy"          ascii wide nocase
        $tor6 = "tor.exe"           ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($tor*))
}
