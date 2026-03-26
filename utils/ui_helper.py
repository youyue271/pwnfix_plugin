import ida_bytes
import ida_nalt
import idaapi


SEVERITY_COLORS = {
    "high": 0x0000FF,
    "medium": 0x0080FF,
    "low": 0x00FFFF,
}


class VulnChooserView(idaapi.Choose):
    def __init__(self, title, findings):
        super().__init__(
            title,
            [
                ["Address", 10 | idaapi.Choose.CHCOL_HEX],
                ["Function", 24 | idaapi.Choose.CHCOL_PLAIN],
                ["Rule", 20 | idaapi.Choose.CHCOL_PLAIN],
                ["Severity", 10 | idaapi.Choose.CHCOL_PLAIN],
                ["Confidence", 10 | idaapi.Choose.CHCOL_PLAIN],
                ["Description", 60 | idaapi.Choose.CHCOL_PLAIN],
                ["Suggested Fix", 36 | idaapi.Choose.CHCOL_PLAIN],
            ],
            flags=idaapi.Choose.CH_CAN_REFRESH,
        )
        self.findings = findings
        self.items = [
            [
                hex(item.ea),
                item.function_name,
                item.rule_id,
                item.severity.upper(),
                item.confidence.upper(),
                item.description,
                self._fix_summary(item),
            ]
            for item in findings
        ]

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idaapi.jumpto(self.findings[n].ea)
        return (idaapi.Choose.NOTHING_CHANGED,)

    def _fix_summary(self, finding):
        if not finding.fix_actions:
            return ""
        first = finding.fix_actions[0]
        suffix = " [auto-ready]" if first.patchable else ""
        return first.label + suffix


_highlighted_eas = set()


def clear_all_highlights():
    for ea in _highlighted_eas:
        try:
            ida_nalt.set_item_color(ea, 0xFFFFFFFF)
        except Exception:
            pass
    _highlighted_eas.clear()
    idaapi.refresh_idaview_anyway()


def highlight_and_comment(finding):
    if finding.ea in (0, idaapi.BADADDR):
        return

    comment = (
        f"[{finding.rule_id}] {finding.category} "
        f"({finding.severity}/{finding.confidence}) {finding.description}"
    )
    if finding.recommendations:
        comment += f" Fix: {finding.recommendations[0]}"

    ida_bytes.set_cmt(finding.ea, comment, False)
    ida_nalt.set_item_color(
        finding.ea,
        SEVERITY_COLORS.get(finding.severity.lower(), SEVERITY_COLORS["medium"]),
    )
    _highlighted_eas.add(finding.ea)


def show_vulnerabilities(findings):
    ordered_findings = sorted(findings, key=lambda item: (item.ea, item.rule_id))

    for finding in ordered_findings:
        highlight_and_comment(finding)

    idaapi.refresh_idaview_anyway()

    if ordered_findings:
        chooser = VulnChooserView(
            f"Detected Vulnerabilities ({len(ordered_findings)})",
            ordered_findings,
        )
        chooser.Show()
