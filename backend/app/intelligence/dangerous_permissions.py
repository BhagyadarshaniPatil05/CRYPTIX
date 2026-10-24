"""
Knowledge base of dangerous Android permissions.

Severity Levels:
Critical
High
Medium
Low
"""

DANGEROUS_PERMISSIONS = {

    "android.permission.SEND_SMS": {
        "severity": "Critical",
        "reason": "Can send SMS messages without user interaction."
    },

    "android.permission.RECEIVE_SMS": {
        "severity": "Critical",
        "reason": "Can read incoming SMS messages."
    },

    "android.permission.READ_SMS": {
        "severity": "Critical",
        "reason": "Allows reading user's SMS messages."
    },

    "android.permission.RECORD_AUDIO": {
        "severity": "High",
        "reason": "Can record audio using the microphone."
    },

    "android.permission.CAMERA": {
        "severity": "High",
        "reason": "Allows access to the device camera."
    },

    "android.permission.READ_CONTACTS": {
        "severity": "High",
        "reason": "Can access the user's contacts."
    },

    "android.permission.WRITE_CONTACTS": {
        "severity": "High",
        "reason": "Can modify the user's contacts."
    },

    "android.permission.ACCESS_FINE_LOCATION": {
        "severity": "High",
        "reason": "Can access precise device location."
    },

    "android.permission.ACCESS_COARSE_LOCATION": {
        "severity": "Medium",
        "reason": "Can access approximate device location."
    },

    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "severity": "Medium",
        "reason": "Can modify files stored on external storage."
    },

    "android.permission.READ_EXTERNAL_STORAGE": {
        "severity": "Medium",
        "reason": "Can read files stored on external storage."
    },

    "android.permission.INTERNET": {
        "severity": "Low",
        "reason": "Allows internet communication."
    }

}