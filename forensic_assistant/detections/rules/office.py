import ntpath
from forensic_assistant.detections.models import Rule


class OfficeChild(Rule):
    def evaluate(self, db, event, parameters):
        parent = ntpath.basename(event["parent_process_name"] or "").casefold()
        child = ntpath.basename(event["process_name"] or "").casefold()
        if parent in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"} and child in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            return self.observation(event, f"The process creation record reports {parent} as parent of {child}",
                limitations=["The reported parent fields do not establish that a separate parent creation record is available",
                             "Office automation and administration are possible; this is not proof of compromise"])


RULES = [OfficeChild("LOCARD-PROC-001", "Office application spawned command interpreter",
                    "Review a process event reporting an Office parent and command-interpreter child", "medium", "1", ("process",))]
