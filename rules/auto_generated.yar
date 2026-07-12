rule RedTeam_LSASS_Dump {
    meta:
        author = "Senior Detection Engineer"
    strings:
        $a = "lsass-dump" wide
    condition:
        $a in themself() and file_path: contains("Documents") and file_path: ends_with(".txt")
}