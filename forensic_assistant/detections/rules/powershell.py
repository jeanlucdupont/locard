import ntpath
import re
from forensic_assistant.detections.models import Rule

INDICATORS = {
    "EncodedCommand": r"(?i)(?<![\w-])-(?:enc|encodedcommand)(?=\s|:|$)",
    "Invoke-WebRequest": r"(?i)(?<![\w-])Invoke-WebRequest(?![\w-])",
    "Invoke-Expression": r"(?i)(?<![\w-])Invoke-Expression(?![\w-])",
    "IEX": r"(?i)(?<![\w])IEX(?![\w])",
    "DownloadString": r"(?i)(?<![\w])DownloadString(?![\w])",
    "FromBase64String": r"(?i)(?<![\w])FromBase64String(?![\w])",
}


class PowerShellCharacteristics(Rule):
    def evaluate(self, db, event, parameters):
        if event["kind"] != "powershell" and ntpath.basename(event["process_name"] or "").casefold() not in ("powershell.exe", "pwsh.exe"):
            return None
        content = "\n".join(event.get(field) or "" for field in ("command_line", "script_block"))
        found = [name for name, pattern in INDICATORS.items() if re.search(pattern, content)]
        if found:
            return self.observation(event, "Lexical PowerShell indicators: " + ", ".join(found),
                limitations=["Matches may appear in comments, strings, or legitimate administration",
                             "No script is executed or decoded; fragmented/truncated logging can hide context"])


RULES = [PowerShellCharacteristics("LOCARD-PS-001", "PowerShell characteristics worth review",
    "Review selected encoded-command, download, and expression-evaluation indicators", "medium", "1", ("process", "powershell"))]
