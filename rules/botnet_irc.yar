/*
    YARA Rules: IRC Botnet Detection
    Covers: classic IRC bots, modern variants, hidden IRC channels
*/

rule Botnet_IRC_Classic {
    meta:
        description = "Classic IRC Botnet - JOIN/PRIVMSG commands"
        author = "EXE Scanner"
        severity = "CRITICAL"
        category = "botnet"
        family = "IRC"
    strings:
        $irc_join    = "JOIN #"       ascii wide nocase
        $irc_privmsg = "PRIVMSG"      ascii wide nocase
        $irc_nick    = "NICK "        ascii wide nocase
        $irc_pass    = "PASS "        ascii wide nocase
        $irc_user    = "USER "        ascii wide nocase
        $cmd_dl      = "!download"    ascii wide nocase
        $cmd_up      = "!update"      ascii wide nocase
        $cmd_ddos    = "!ddos"        ascii wide nocase
        $cmd_spread  = "!spread"      ascii wide nocase
        $cmd_kill    = "!kill"        ascii wide nocase
        $cmd_exec    = "!exec"        ascii wide nocase
        $cmd_scan    = "!scan"        ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($irc_*)) and
        (1 of ($cmd_*))
}

rule Botnet_IRC_Port_6667 {
    meta:
        description = "IRC bot connecting to port 6667 (standard IRC)"
        severity = "HIGH"
        category = "botnet"
    strings:
        $irc1 = "irc."    ascii wide nocase
        $irc2 = "efnet"   ascii wide nocase
        $irc3 = "undernet" ascii wide nocase
        $irc4 = "dalnet"  ascii wide nocase
        $port1 = { 1A 0B }   // 6667 little-endian
        $port2 = { 70 0B }   // 6768
        $port3 = { 71 0B }   // 6769
        $join  = "JOIN #"  ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ($join) and
        (1 of ($irc*) or 1 of ($port*))
}

rule Botnet_IRC_SSL_Encrypted {
    meta:
        description = "IRC bot using SSL/TLS on non-standard ports"
        severity = "HIGH"
        category = "botnet"
    strings:
        $ssl1  = "SSL_connect"       ascii wide
        $ssl2  = "SSL_CTX_new"       ascii wide
        $ssl3  = "TLSv1_client_method" ascii wide
        $nick  = "NICK "             ascii wide nocase
        $priv  = "PRIVMSG"           ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($ssl*)) and ($nick) and ($priv)
}

rule Botnet_IRC_Mirai_Variant {
    meta:
        description = "Mirai-style IoT botnet IRC command structure"
        severity = "CRITICAL"
        category = "botnet"
        family = "Mirai"
    strings:
        $m1 = "PING :"      ascii wide
        $m2 = "PONG :"      ascii wide
        $m3 = "!udpflood"   ascii wide nocase
        $m4 = "!tcpflood"   ascii wide nocase
        $m5 = "!synflood"   ascii wide nocase
        $m6 = "!httpflood"  ascii wide nocase
        $m7 = "!slowloris"  ascii wide nocase
        $m8 = "botnet"      ascii wide nocase
        $m9 = "/bin/busybox" ascii
        $m10 = "MIRAI"      ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($m*))
}

rule Botnet_IRC_Keylogger_Exfil {
    meta:
        description = "IRC bot with keylogger and data exfiltration"
        severity = "CRITICAL"
        category = "botnet,spyware"
    strings:
        $kl1 = "SetWindowsHookEx"  ascii wide
        $kl2 = "GetAsyncKeyState"  ascii wide
        $kl3 = "GetKeyboardState"  ascii wide
        $irc = "PRIVMSG"           ascii wide nocase
        $ex1 = "clip"              ascii wide nocase  // clipboard
        $ex2 = "screenshot"        ascii wide nocase
        $ex3 = "keylog"            ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ($irc) and
        (1 of ($kl*)) and
        (1 of ($ex*))
}

rule Botnet_IRC_Hidden_Channel {
    meta:
        description = "IRC bot using obfuscated/encoded channel names"
        severity = "HIGH"
        category = "botnet,stealth"
    strings:
        // Encoded JOIN patterns
        $j1 = "JOIN" ascii wide nocase
        // XOR obfuscated IRC keywords (common patterns)
        $xor1 = { 4A 4F 49 4E 20 23 }  // "JOIN #" raw
        $xor2 = { 50 52 49 56 4D 53 47 }  // "PRIVMSG" raw
        // Base64 of IRC commands
        $b64_join = "Sk9JTiAj"  // base64("JOIN #")
        $b64_priv = "UFJJV01TRw==" // base64("PRIVMSG")
    condition:
        uint16(0) == 0x5A4D and
        (($j1 and ($b64_join or $b64_priv)) or
         ($xor1 and $xor2))
}
