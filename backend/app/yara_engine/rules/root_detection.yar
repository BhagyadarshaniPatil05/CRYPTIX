rule RootDetection
{
    meta:
        author = "CRYPTIX"
        description = "Detect root related commands"
        severity = "Critical"

    strings:
        $su = "su"
        $busybox = "busybox"
        $chmod = "chmod"

    condition:
        2 of them
}