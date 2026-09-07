import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from boyer_moore import boyer_moore
from aho_corasick import aho_corasick

def message_part(line):
    parts = line.split(" - ", 2)
    return parts[2].strip() if len(parts) == 3 else line.strip()

def alpha_only(s):
    return re.sub(r"[^A-Za-z]", "", s)

def search_messages(message_log_path, patterns):
    try:
        with open(message_log_path, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []
    
    results = []

    if len(patterns) == 1:
        pattern = alpha_only(patterns[0]).upper()

        for i, line in enumerate(lines):
            msg = alpha_only(message_part(line))
            idx = boyer_moore(msg, pattern)
            
            if idx != -1:
                results.append((i + 1, line.strip(), [idx]))

    else:
        upper_patterns = [p.upper() for p in patterns]

        for i, line in enumerate(lines):
            msg = message_part(line).upper()
            matches = aho_corasick(msg, upper_patterns)

            if matches and matches != -1:
                results.append((i + 1, line.strip(), matches))

    return results
