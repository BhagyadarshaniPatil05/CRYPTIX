API_PATTERNS = {

    "Runtime.exec": {
        "category": "Command Execution",
        "severity": "High",
        "reason": "Executes shell commands."
    },

    "ProcessBuilder": {
        "category": "Command Execution",
        "severity": "High",
        "reason": "Creates operating system processes."
    },

    "DexClassLoader": {
        "category": "Dynamic Loading",
        "severity": "Critical",
        "reason": "Loads code dynamically."
    },

    "PathClassLoader": {
        "category": "Dynamic Loading",
        "severity": "Medium",
        "reason": "Loads application classes."
    },

    "Class.forName": {
        "category": "Reflection",
        "severity": "Medium",
        "reason": "Reflection API."
    },

    "Method.invoke": {
        "category": "Reflection",
        "severity": "Medium",
        "reason": "Reflection method invocation."
    },

    "Cipher": {
        "category": "Cryptography",
        "severity": "Low",
        "reason": "Encryption API."
    },

    "MessageDigest": {
        "category": "Cryptography",
        "severity": "Low",
        "reason": "Hashing API."
    },

    "HttpURLConnection": {
        "category": "Networking",
        "severity": "Low",
        "reason": "HTTP communication."
    },

    "Socket": {
        "category": "Networking",
        "severity": "Medium",
        "reason": "Raw socket communication."
    },

    "SmsManager": {
        "category": "SMS",
        "severity": "Critical",
        "reason": "Can send SMS messages."
    },

    "TelephonyManager": {
        "category": "Device Info",
        "severity": "Medium",
        "reason": "Accesses device identifiers."
    },

    "LocationManager": {
        "category": "Location",
        "severity": "Medium",
        "reason": "Accesses location."
    },

    "FileInputStream": {
        "category": "File System",
        "severity": "Low",
        "reason": "Reads local files."
    },

    "FileOutputStream": {
        "category": "File System",
        "severity": "Low",
        "reason": "Writes local files."
    }
}