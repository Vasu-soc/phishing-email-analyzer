import os
import re
from typing import Tuple

def parse_email_text(text: str) -> Tuple[str, str]:
    """
    Parses email subject and body from a single string.
    Looks for a line starting with 'Subject:' (case-insensitive) at the beginning of the text.
    If found, extracts it as the subject and treats the rest of the text as the body.
    """
    if not text:
        return "", ""
        
    subject = ""
    body = text

    # Regex to find "Subject: [content]" at the beginning, allowing leading whitespace/newlines
    match = re.search(r'^\s*Subject:\s*(.*?)\r?\n', text, re.IGNORECASE)
    if match:
        subject = match.group(1).strip()
        # The body is everything after the match end
        body = text[match.end():].strip()
    else:
        # Check if subject starts on the first line even without "Subject:" header,
        # but only if there is a blank line separating it from the body.
        # Otherwise, default to empty subject and entire text as body.
        lines = text.splitlines()
        if len(lines) > 1 and lines[1].strip() == "":
            subject = lines[0].strip()
            body = "\n".join(lines[2:]).strip()
            
    return subject, body


def read_email_file(file_path: str) -> Tuple[str, str]:
    """
    Reads the content of a text file and parses the subject and body.
    Raises FileNotFoundError or PermissionError on file issues.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
        
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        raise IOError(f"Failed to read file {file_path}: {e}")

    return parse_email_text(content)
