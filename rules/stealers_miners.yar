/*
    YARA Rules: Info Stealers (Credential Theft)
*/

rule Stealer_Generic_Password {
    meta:
        description = "Generic password / credential stealer behavior"
        severity = "CRITICAL"
        category = "stealer,credential"
    strings:
        // Browser paths targeted
        $br1 = "Login Data"             ascii wide  // Chrome SQLite
        $br2 = "key4.db"                ascii wide  // Firefox
        $br3 = "logins.json"            ascii wide  // Firefox
        $br4 = "cookies.sqlite"         ascii wide  // Firefox
        $br5 = "Web Data"               ascii wide  // Chrome
        $br6 = "Cookies"                ascii wide  // Chrome/Edge
        // Crypto wallets
        // Email clients
        // Exfil APIs
        $ex1 = "HttpSendRequest"        ascii wide
        $ex2 = "WinHttpSendRequest"     ascii wide
        $ex3 = "PRIVMSG"                ascii wide  // IRC exfil
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($br*)) and
        (1 of ($ex*))
}

rule Stealer_Redline {
    meta:
        description = "RedLine Stealer — popular MaaS credential stealer"
        severity = "CRITICAL"
        category = "stealer,credential"
        family = "RedLine"
    strings:
        $r1 = "RedLine"             ascii wide nocase
        $r2 = "red-line"            ascii wide nocase
        // RedLine targets
        $t1 = "Electrum"            ascii wide
        $t2 = "Exodus"              ascii wide
        $t3 = "MetaMask"            ascii wide
        $t4 = "Telegram"            ascii wide nocase
        $t5 = "Discord"             ascii wide nocase
        $t6 = "Steam"               ascii wide nocase
        // RedLine config
        $c1 = "IP:Port"             ascii wide
        $c2 = "BuildID"             ascii wide
        $c3 = "GetBrowsers"         ascii wide
        $c4 = "GetWallets"          ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($r*)) or
        (3 of ($t*) and 2 of ($c*))
}

rule Stealer_Vidar {
    meta:
        description = "Vidar Stealer — successor to Arkei"
        severity = "CRITICAL"
        category = "stealer,credential"
        family = "Vidar"
    strings:
        $v1 = "Vidar"               ascii wide nocase
        $v2 = "arkei"               ascii wide nocase
        // Vidar C2 communication (uses Mastodon/Steam profiles for C2)
        $c1 = "steamcommunity.com"  ascii wide nocase
        $c2 = "mastodon.social"     ascii wide nocase
        // Vidar stealer behavior
        $s1 = "autofill"            ascii wide nocase
        $s2 = "credit_card"         ascii wide nocase
        $s3 = "crypto"              ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($v*)) or
        (1 of ($c*) and 2 of ($s*))
}

rule Stealer_FormBook {
    meta:
        description = "FormBook — form grabber and stealer"
        severity = "CRITICAL"
        category = "stealer,formgrabber"
        family = "FormBook"
    strings:
        $f1 = "FormBook"            ascii wide nocase
        // FormBook injects into browser process
        $i2 = "HttpSendRequestA"    ascii wide
        $i3 = "PR_Write"            ascii wide   // Firefox SSL hook
        $i4 = "PR_Read"             ascii wide   // Firefox SSL hook
        // Form grabbing APIs
        $g1 = "FindWindowExA"       ascii wide
        $g2 = "SendMessage"         ascii wide
        $g3 = "GetWindowText"       ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($f1) or
        ($i3 and $i4 and $i2 and 1 of ($g*))
}

rule Stealer_Crypto_Wallet {
    meta:
        description = "Crypto wallet stealer — targets multiple blockchain wallets"
        severity = "CRITICAL"
        category = "stealer,crypto"
    strings:
        // Wallet files
        $w1 = "wallet.dat"          ascii wide
        $w2 = ".wallet"             ascii wide
        $w3 = "keystore"            ascii wide
        $w4 = "seed phrase"         ascii wide nocase
        $w5 = "mnemonic"            ascii wide nocase
        $w6 = "private key"         ascii wide nocase
        // Wallet software
        $s1 = "Electrum"            ascii wide
        $s2 = "Exodus"              ascii wide
        $s3 = "Atomic"              ascii wide
        $s4 = "MetaMask"            ascii wide
        $s5 = "Coinomi"             ascii wide
        $s6 = "Jaxx"                ascii wide
        $s7 = "Ledger"              ascii wide nocase
        // Copy operation
        $cp1 = "CopyFile"           ascii wide
        $cp2 = "MoveFile"           ascii wide
        $cp3 = "SHFileOperation"    ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($w*) or 3 of ($s*)) and
        (1 of ($cp*))
}

/*
    YARA Rules: Cryptominer Detection
*/

rule Miner_XMRig {
    meta:
        description = "XMRig Monero CPU miner (malicious deployment)"
        severity = "HIGH"
        category = "miner,cryptominer"
        family = "XMRig"
    strings:
        $x1 = "xmrig"              ascii wide nocase
        $x2 = "XMRig"              ascii wide
        $x3 = "monero"             ascii wide nocase
        $x4 = "stratum+"           ascii wide nocase
        $x5 = "randomx"            ascii wide nocase
        $x6 = "xmr-stak"           ascii wide nocase
        // Mining pool patterns
        $p1 = "pool.supportxmr.com"   ascii wide nocase
        $p2 = "xmrpool.eu"            ascii wide nocase
        $p3 = "minexmr.com"           ascii wide nocase
        $p4 = "nanopool.org"          ascii wide nocase
        // Config format
        $c1 = "\"algo\""           ascii wide
        $c2 = "\"donate-level\""   ascii wide
        $c3 = "\"threads\""        ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($x*)) or
        (1 of ($p*)) or
        (2 of ($c*))
}

rule Miner_Hidden_Process {
    meta:
        description = "Hidden cryptominer — hides CPU usage, injects into system process"
        severity = "CRITICAL"
        category = "miner,cryptominer,stealth"
    strings:
        $m1 = "stratum"             ascii wide nocase
        $m2 = "mining"              ascii wide nocase
        $m3 = "hashrate"            ascii wide nocase
        $m4 = "CryptoNight"         ascii wide nocase
        $m5 = "ethash"              ascii wide nocase
        // Injection for hiding
        $inj1 = "VirtualAllocEx"    ascii wide
        $inj2 = "WriteProcessMemory" ascii wide
        $inj3 = "CreateRemoteThread" ascii wide
        // CPU throttling (hide from task manager)
        $cpu1 = "GetSystemInfo"     ascii wide
        $cpu2 = "SetPriorityClass"  ascii wide
        $cpu3 = "SetThreadPriority" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($m*)) and
        (($inj1 and $inj2 and $inj3) or
         (2 of ($cpu*)))
}

rule Miner_Clipboard_Hijack {
    meta:
        description = "Clipper — replaces crypto addresses in clipboard"
        severity = "HIGH"
        category = "stealer,clipper,crypto"
    strings:
        // Clipboard APIs
        $c1 = "OpenClipboard"       ascii wide
        $c2 = "GetClipboardData"    ascii wide
        $c3 = "SetClipboardData"    ascii wide
        $c4 = "EmptyClipboard"      ascii wide
        // Crypto address patterns (regex-like strings in binary)
        // Timer for monitoring clipboard
        $t1 = "SetTimer"            ascii wide
        $t2 = "GetTickCount"        ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($c1 and $c2 and $c3 and $c4) and
        (1 of ($t*))
}
