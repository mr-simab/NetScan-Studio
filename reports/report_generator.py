import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any
from engines import ScanResult
from utils import VERSION, AUTHOR, TAGLINE
from utils.logger import get_logger

logger = get_logger("ReportGenerator")


class ReportGenerator:
    """Generates professional scan reports"""

    def __init__(self):
        self.timestamp = datetime.now()

    # -------------------- TXT REPORT -------------------- #
    def generate_txt_report(self, target: str, mode: str, tool: str,
                            results: List[ScanResult], insights: Dict[str, Any],
                            config: Dict = None) -> str:

        lines = []
        sep = "=" * 80

        # Header
        lines.extend([
            sep,
            f"{'NetScan Studio':^80}",
            f"{TAGLINE:^80}",
            sep,
            f"\nAuthor: {AUTHOR}",
            f"Version: {VERSION}",
            f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        ])

        # Config
        lines.extend([
            f"\n{sep}",
            "SCAN CONFIGURATION",
            sep,
            f"Target: {target}",
            f"Mode: {mode}",
            f"Tool: {tool}"
        ])

        if config:
            for k, v in config.items():
                if k != "target":
                    lines.append(f"{k.replace('_', ' ').title()}: {v}")

        # Results
        lines.extend([
            f"\n{sep}",
            "SCAN RESULTS",
            sep
        ])

        if results:
            lines.append(f"\n{'Port':<8} {'Service':<20} {'State':<12} {'Version':<30}")
            lines.append("-" * 80)

            for r in sorted(results, key=lambda x: x.port):
                lines.append(
                    f"{r.port:<8} {r.service:<20} {r.state:<12} {(r.version or '-'): <30}"
                )
        else:
            lines.append("No open ports detected")

        # Insights
        lines.extend([
            f"\n{sep}",
            "ANALYSIS & INSIGHTS",
            sep
        ])

        if insights:
            lines.append(f"\nSummary: {insights.get('summary', 'N/A')}")
            lines.append(f"Risk Level: {insights.get('risk_level', 'N/A').upper()}")

            if insights.get("insights"):
                lines.append("\nKey Findings:")
                for i in insights["insights"]:
                    lines.append(f"  • {i}")

            if insights.get("recommendations"):
                lines.append("\nRecommendations:")
                for r in insights["recommendations"]:
                    lines.append(f"  • {r}")

        lines.extend([f"\n{sep}", "END OF REPORT", sep])

        return "\n".join(lines)

    # -------------------- JSON REPORT -------------------- #
    def generate_json_report(self, target: str, mode: str, tool: str,
                             results: List[ScanResult], insights: Dict[str, Any],
                             config: Dict = None) -> str:

        from processing import ResultsParser

        data = {
            "metadata": {
                "app": "NetScan Studio",
                "tagline": TAGLINE,
                "author": AUTHOR,
                "version": VERSION,
                "timestamp": self.timestamp.isoformat(),
            },
            "scan": {
                "target": target,
                "mode": mode,
                "tool": tool,
                **(config or {})
            },
            "results": ResultsParser.to_dict_list(results),
            "insights": insights
        }

        return json.dumps(data, indent=2)

    # -------------------- CSV REPORT -------------------- #
    def generate_csv_report(self, results: List[ScanResult]) -> str:
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(["Port", "Service", "State", "Version"])

        for r in sorted(results, key=lambda x: x.port):
            writer.writerow([r.port, r.service, r.state, r.version or ""])

        return output.getvalue()

    # -------------------- SAVE REPORT -------------------- #
    def save_report(self, filename: str, content: str, format: str = 'txt'):
        try:
            # Auto-create directory if needed
            os.makedirs(os.path.dirname(filename), exist_ok=True)

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"Report saved: {filename}")
            return True, f"Report saved to {filename}"

        except Exception as e:
            logger.error(f"Save failed: {e}")
            return False, str(e)

    # -------------------- AUTO FILENAME -------------------- #
    def generate_filename(self, target: str, format: str = "txt") -> str:
        safe_target = target.replace(".", "_")
        timestamp = self.timestamp.strftime("%Y%m%d_%H%M%S")
        return f"reports/{safe_target}_{timestamp}.{format}"