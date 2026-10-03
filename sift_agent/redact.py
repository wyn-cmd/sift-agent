import re

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RE = re.compile(r'(?i)(\\users\\)([^\\\s]+)')
HOST_RE = re.compile(r'(?i)(\\\\)([A-Za-z0-9_-]+)')

# Mask text that identifies people or networks before a report leaves the lab: IP addresses,
# user names in profile paths and UNC host names. The report body is kept readable otherwise.
def redact(text: str) -> str:
    text = IP_RE.sub('[ip]', text)
    text = USER_RE.sub(r'\1[user]', text)
    text = HOST_RE.sub(r'\1[host]', text)
    return text
