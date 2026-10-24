rule Networking
{
    meta:
        author = "CRYPTIX"
        description = "Detect networking APIs"
        severity = "Low"

    strings:
        $http = "HttpURLConnection"
        $socket = "Socket"

    condition:
        any of them
}