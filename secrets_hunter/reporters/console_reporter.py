from typing import List
from secrets_hunter.models import Finding


class ConsoleReporter:
    @staticmethod
    def format_report(findings: List[Finding]) -> None:
        if not findings:
            print("No secrets detected!")
            return

        count = len(findings)
        plural = "s" if count != 1 else ""
        report = [f"\n⚠️  Found {count} potential secret{plural}:\n", "=" * 80]

        for finding in findings:
            report.append(f"\nFile: {finding.file}")
            report.append(f"  Line {finding.line}: {finding.type}")

            # Clean up match string (remove ellipsis if present)
            match_string = finding.match.replace('...', '') if finding.match else ''
            report.append(f"    Match: {match_string}")

            # Show detection method info
            if finding.detection_method == 'entropy':
                report.append(f"    Detection: Entropy-based (Confidence: {finding.confidence}%)")
                if finding.context_var:
                    report.append(f"    Variable: {finding.context_var}")
            else:
                report.append(f"    Detection: {finding.detection_method} (Confidence: {finding.confidence}%)")

            # Show context
            if finding.context:
                report.append(f"    Context: {finding.context}")

            report.append("-" * 80)
        
        print("\n".join(report))
