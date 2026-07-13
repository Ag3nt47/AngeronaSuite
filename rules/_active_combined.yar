/*
 * Angerona — local signature ruleset (defensive detection signatures).
 * These identify well-known malicious indicators. Tune / extend freely.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard anti-malware test file"
        severity = "medium"
    strings:
        // Match the unique EICAR marker (no backslash escaping pitfalls).
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell download-and-execute / encoded-command pattern"
        severity = "high"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase
        $c = "Invoke-Expression" nocase
        $d = "FromBase64String" nocase
        $e = "-enc " nocase
        $f = "-EncodedCommand" nocase
    condition:
        2 of them
}

rule Mimikatz_Credential_Dumper
{
    meta:
        description = "Mimikatz credential-theft tool indicators"
        severity = "critical"
    strings:
        $a = "sekurlsa" nocase
        $b = "mimikatz" nocase
        $c = "logonpasswords" nocase
        $d = "kerberos::" nocase
        $e = "gentilkiwi" nocase
    condition:
        any of them
}

rule WebShell_Eval_Backdoor
{
    meta:
        description = "Common PHP/ASP webshell eval backdoor"
        severity = "high"
    strings:
        $a = "eval($_POST" nocase
        $b = "eval($_GET" nocase
        $c = "eval(base64_decode" nocase
        $d = "system($_REQUEST" nocase
        $e = "Request.Item" nocase
    condition:
        any of them
}

rule Ransom_Note_Language
{
    meta:
        description = "Phrasing common to ransomware ransom notes"
        severity = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "decrypt your files" nocase
        $c = "send bitcoin" nocase
        $d = ".onion" nocase
    condition:
        2 of them
}


// ── auto-generated (evolution engine) ──
rule Red_Team_Tagged_Process {
    meta:
        author = "Senior Detection Engineer"
    strings:
        $tag = "red-team-tagged" wide
    condition:
        all of them {
            5 of ($tag in /proc/self/cmdline/)
        }
}