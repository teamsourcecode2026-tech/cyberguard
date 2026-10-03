# intelligent_detection/known_bad_hashes.py
# Small demo list of known-malicious file hashes (SHA-256).
# In production this would come from a live threat-intel feed
# (e.g. VirusTotal, MalwareBazaar) rather than a hardcoded list.

KNOWN_BAD_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0": "EICAR-Test-File",
}

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".bat", ".vbs", ".js", ".ps1", ".jar", ".msi"}

DOCUMENT_LIKE_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}

SUSPICIOUS_STRINGS = [
    "powershell -enc", "powershell.exe -e", "cmd.exe /c", "wscript.shell",
    "createremotethread", "virtualallocex", "writeprocessmemory",
    "autoopen", "shell.application", "regcreatekeyex", "urldownloadtofile",
    "invoke-expression", "downloadstring", "bitstransfer",
]