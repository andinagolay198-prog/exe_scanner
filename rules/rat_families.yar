/*
    YARA Rules: RAT (Remote Access Trojans)
    Covers: njRAT, DarkComet, AsyncRAT, Quasar, NanoCore
*/

rule RAT_njRAT {
    meta:
        description = "njRAT / Bladabindi — popular Middle-Eastern RAT"
        severity = "CRITICAL"
        category = "rat,backdoor"
        family = "njRAT"
    strings:
        $n1 = "njRAT"           ascii wide nocase
        $n2 = "Bladabindi"      ascii wide nocase
        $n3 = "HackerOne"       ascii wide nocase
        // njRAT mutex patterns
        // njRAT specific strings
        $s1 = "l!l@l#l$l%l^l"  ascii wide  // njRAT separator
        $s2 = "kl|"             ascii wide  // keylog prefix
        $s3 = "P|"              ascii wide  // ping command
        $s4 = "CAM|"            ascii wide  // webcam command
        $s5 = "RG|"             ascii wide  // registry command
        $s6 = "un|"             ascii wide  // uninstall
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($n*) or
         (3 of ($s*)) or
         ($s1 and 1 of ($s2,$s3,$s4)))
}

rule RAT_AsyncRAT {
    meta:
        description = "AsyncRAT — open-source .NET RAT"
        severity = "CRITICAL"
        category = "rat,backdoor"
        family = "AsyncRAT"
    strings:
        $a1 = "AsyncRAT"        ascii wide nocase
        $a2 = "AsyncClient"     ascii wide nocase
        $a3 = "Pastebin"        ascii wide nocase
        // AsyncRAT config markers
        $c1 = "Ports"           ascii wide
        $c2 = "Hosts"           ascii wide
        $c3 = "Version"         ascii wide
        $c4 = "Install"         ascii wide
        $c5 = "MTX"             ascii wide  // mutex key
        $c6 = "Certificate"     ascii wide
        // Commands
        $cmd1 = "sendPlugin"    ascii wide nocase
        $cmd2 = "savePlugin"    ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($a*)) or
        (4 of ($c*) and 1 of ($cmd*))
}

rule RAT_Quasar {
    meta:
        description = "Quasar RAT — open-source .NET remote admin tool (malicious use)"
        severity = "CRITICAL"
        category = "rat,backdoor"
        family = "Quasar"
    strings:
        $q1 = "Quasar"          ascii wide nocase
        $q2 = "xRAT"            ascii wide nocase
        // Quasar packets
        $p1 = "GetDesktop"      ascii wide
        $p2 = "GetKeylogger"    ascii wide
        $p3 = "GetPassword"     ascii wide
        $p4 = "DoShellExecute"  ascii wide
        $p5 = "DoDownloadFile"  ascii wide
        $p6 = "GetMonitors"     ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($q*) and 2 of ($p*)) or
        (4 of ($p*))
}

rule RAT_DarkComet {
    meta:
        description = "DarkComet RAT by DarkCoderSc"
        severity = "CRITICAL"
        category = "rat,backdoor"
        family = "DarkComet"
    strings:
        $d1 = "DarkComet"           ascii wide nocase
        $d2 = "DarkCoderSc"         ascii wide nocase
        $d3 = "#KCMDDC"             ascii wide     // DarkComet mutex prefix
        $d4 = "SETTINGS"            ascii wide
        $d5 = "PERSIST"             ascii wide
        $d6 = "DNSCACHE"            ascii wide
        // DarkComet protocol markers
        $p1 = "PING|"               ascii wide
        $p2 = "KLOG|"               ascii wide
        $p3 = "SHF|"                ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($d1,$d2,$d3) or
         (2 of ($d4,$d5,$d6) and 1 of ($p*)))
}

rule RAT_NanoCore {
    meta:
        description = "NanoCore RAT — .NET-based commercial RAT"
        severity = "CRITICAL"
        category = "rat,backdoor"
        family = "NanoCore"
    strings:
        $n1 = "NanoCore"            ascii wide nocase
        $n2 = "ClientPlugin"        ascii wide
        $n3 = "CoreClientPlugin"    ascii wide
        $n4 = "PluginCommand"       ascii wide
        $n5 = "IClientLoggingPlugin" ascii wide
        $n6 = "IClientNetworkPlugin" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($n1,$n2,$n3)) or
        (3 of ($n*))
}
