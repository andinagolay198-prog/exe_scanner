/*
    YARA Rules: HTTP/HTTPS Botnet C2 Detection
    Covers: HTTP C2, beaconing, domain generation algorithm (DGA)
*/

rule Botnet_HTTP_C2_Basic {
    meta:
        description = "HTTP-based C2 communication pattern"
        severity = "HIGH"
        category = "botnet"
        family = "HTTP C2"
    strings:
        $ua1 = "Mozilla/4.0"    ascii wide
        $ua2 = "Mozilla/5.0"    ascii wide
        $ua3 = "User-Agent:"    ascii wide nocase
        $h1  = "Content-Type:"  ascii wide nocase
        $h2  = "Accept:"        ascii wide nocase
        $cmd1 = "cmd="          ascii wide nocase
        $cmd2 = "command="      ascii wide nocase
        $cmd3 = "task="         ascii wide nocase
        $cmd4 = "job="          ascii wide nocase
        $api1 = "InternetOpenUrl"   ascii wide
        $api2 = "HttpSendRequest"   ascii wide
        $api3 = "WinHttpOpen"       ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($api*)) and
        (1 of ($ua*) or 1 of ($h*)) and
        (1 of ($cmd*))
}

rule Botnet_HTTP_Beacon {
    meta:
        description = "Periodic HTTP beaconing to C2 server"
        severity = "HIGH"
        category = "botnet,c2"
    strings:
        $sleep = "Sleep"            ascii wide
        $http  = "WinHttpOpen"      ascii wide
        $post  = "POST"             ascii wide nocase
        $get   = "GET /"            ascii wide nocase
        $b1    = "heartbeat"        ascii wide nocase
        $b2    = "checkin"          ascii wide nocase
        $b3    = "beacon"           ascii wide nocase
        $b4    = "ping"             ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ($sleep) and ($http) and
        (1 of ($b*)) and
        (($post or $get))
}

rule Botnet_DGA_Domain_Generation {
    meta:
        description = "Domain Generation Algorithm - bot generates C2 domains dynamically"
        severity = "CRITICAL"
        category = "botnet,evasion"
    strings:
        // Math functions used for DGA
        $math1 = "GetSystemTime"    ascii wide
        $math2 = "GetTickCount"     ascii wide
        $math3 = "_time64"          ascii wide
        // DNS resolution
        $dns1  = "gethostbyname"    ascii wide
        $dns2  = "WSAStartup"       ascii wide
        $dns3  = "getaddrinfo"      ascii wide
        // Common TLDs used by DGA
        $tld1  = ".xyz"             ascii wide nocase
        $tld2  = ".top"             ascii wide nocase
        $tld3  = ".club"            ascii wide nocase
        $tld4  = ".ru"              ascii wide nocase
        $tld5  = ".pw"              ascii wide nocase
        // Fallback C2 (DGA always has fallback)
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($math*)) and (1 of ($dns*)) and
        (2 of ($tld*))
}

rule Botnet_Zeus_Zbot {
    meta:
        description = "Zeus/Zbot banking trojan patterns"
        severity = "CRITICAL"
        category = "botnet,banker,trojan"
        family = "Zeus"
    strings:
        // Zeus config file markers
        $z1 = "bot_id"          ascii wide nocase
        $z2 = "keylog_post"     ascii wide nocase
        $z3 = "form_grabber"    ascii wide nocase
        $z4 = "webinjects"      ascii wide nocase
        $z5 = "httpinject"      ascii wide nocase
        // Zeus API usage
        $api1 = "NtCreateSection"    ascii wide
        $api2 = "NtMapViewOfSection" ascii wide
        $api3 = "NtQuerySystemInformation" ascii wide
        // Zeus registry
        $wh   = "SetWindowsHookEx"  ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($z*) or
         ($wh and 2 of ($api*)))
}

rule Botnet_Emotet_Loader {
    meta:
        description = "Emotet/Geodo botnet loader characteristics"
        severity = "CRITICAL"
        category = "botnet,loader"
        family = "Emotet"
    strings:
        // Emotet uses multiple C2 IPs
        $e1 = "WinHttpConnect"      ascii wide
        $e2 = "WinHttpSendRequest"  ascii wide
        $e3 = "WinHttpReceiveResponse" ascii wide
        // Emotet persistence
        $p1 = "CurrentVersion\\Run" ascii wide nocase
        $p2 = "schtasks"            ascii wide nocase
        $p3 = "netsh"               ascii wide nocase
        // Emotet process
        $proc1 = "powershell"       ascii wide nocase
        $proc2 = "wscript"          ascii wide nocase
        $proc3 = "cscript"          ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($e*)) and
        (1 of ($p*)) and
        (1 of ($proc*))
}

rule Botnet_TrickBot_Module {
    meta:
        description = "TrickBot modular banking trojan"
        severity = "CRITICAL"
        category = "botnet,banker"
        family = "TrickBot"
    strings:
        $t1 = "module_name"     ascii wide nocase
        $t2 = "module_config"   ascii wide nocase
        $t3 = "group_tag"       ascii wide nocase
        $t4 = "client_id"       ascii wide nocase
        $t5 = "psfin"           ascii wide nocase  // financial targets
        $t6 = "pwgrab"          ascii wide nocase  // password grabber
        $t7 = "shareDll"        ascii wide nocase
        $api1 = "BCryptEncrypt" ascii wide
        $api2 = "CryptCreateHash" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($t*)) or
        (2 of ($t*) and 1 of ($api*))
}
