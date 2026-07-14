rule RedTeam_RunKey_Marker {
    meta:
        author = "Senior Detection Engineer"
    strings:
        $marker = "Run-key-named marker written to Documents."
    condition:
        all of them {
            0x20 in ascii and
            contains($marker) and
            file_path contains "_redteam_runkey_" and
            file_path ends with ".txt" and
            file_path starts with "C:\\Users\\"
        }
}