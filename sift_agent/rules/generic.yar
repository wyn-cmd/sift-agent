rule Suspicious_Winsock_Downloader
{
    meta:
        description = "PE that imports networking and process-injection APIs together"
    strings:
        $a = "WSAStartup" ascii
        $b = "InternetOpen" ascii
        $c = "URLDownloadToFile" ascii
        $d = "VirtualAllocEx" ascii
        $e = "WriteProcessMemory" ascii
        $f = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and (1 of ($a, $b, $c)) and 2 of ($d, $e, $f)
}

rule Embedded_PowerShell_Download
{
    meta:
        description = "Strings typical of a PowerShell download cradle"
    strings:
        $a = "DownloadString" ascii wide nocase
        $b = "IEX" ascii wide
        $c = "-EncodedCommand" ascii wide nocase
    condition:
        2 of them
}
