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