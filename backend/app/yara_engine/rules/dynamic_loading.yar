rule DynamicCodeLoading
{
    meta:
        author = "CRYPTIX"
        description = "Detect dynamic code loading"
        severity = "Critical"

    strings:
        $dex = "DexClassLoader"
        $path = "PathClassLoader"

    condition:
        any of them
}