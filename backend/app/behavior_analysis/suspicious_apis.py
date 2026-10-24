SUSPICIOUS_APIS = {

    "Runtime.exec": {
        "severity": "High",
        "reason": "Executes shell commands."
    },

    "ProcessBuilder": {
        "severity": "High",
        "reason": "Creates system processes."
    },

    "DexClassLoader": {
        "severity": "High",
        "reason": "Loads code dynamically."
    },

    "PathClassLoader": {
        "severity": "Medium",
        "reason": "Loads application classes."
    },

    "Class.forName": {
        "severity": "Medium",
        "reason": "Reflection usage."
    },

    "Method.invoke": {
        "severity": "Medium",
        "reason": "Reflection invocation."
    },

    "System.loadLibrary": {
        "severity": "Medium",
        "reason": "Loads native libraries."
    },

    "su": {
        "severity": "Critical",
        "reason": "Root access attempt."
    },

    "busybox": {
        "severity": "High",
        "reason": "BusyBox command usage."
    },

    "chmod": {
        "severity": "Medium",
        "reason": "Changes file permissions."
    }

}