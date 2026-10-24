rule RuntimeExecution
{
    meta:
        author = "CRYPTIX"
        description = "Detect Runtime.exec usage"
        severity = "High"

    strings:
        $runtime = "Runtime.exec"

    condition:
        $runtime
}