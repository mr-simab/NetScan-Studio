import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from engines import ScanResult
from setup import platform_detector
from utils import AUTHOR, TAGLINE, VERSION
from utils.logger import get_logger

logger = get_logger("ReportGenerator")


class ReportGenerator:
    """Generates professional scan reports."""

    def __init__(self):
        self.timestamp = datetime.now()

    def generate_txt_report(
        self,
        target: str,
        mode: str,
        tool: str,
        results: List[ScanResult],
        insights: Dict[str, Any],
        config: Dict = None,
    ) -> str:
        sep = "=" * 80
        lines = [
            sep,
            f"{'NetScan Studio':^80}",
            f"{TAGLINE:^80}",
            sep,
            f"\nAuthor: {AUTHOR}",
            f"Version: {VERSION}",
            f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n{sep}",
            "SCAN CONFIGURATION",
            sep,
            f"Target: {target}",
            f"Mode: {mode}",
            f"Tool: {tool}",
        ]

        if config:
            for key, value in config.items():
                if key != "target":
                    lines.append(f"{key.replace('_', ' ').title()}: {value}")

        lines.extend([f"\n{sep}", "SCAN RESULTS", sep])

        if results:
            lines.append(f"\n{'Port':<8} {'Service':<20} {'State':<12} {'Version':<30}")
            lines.append("-" * 80)

            for result in sorted(results, key=lambda item: item.port):
                lines.append(
                    f"{result.port:<8} {result.service:<20} {result.state:<12} "
                    f"{(result.version or '-'): <30}"
                )
        else:
            lines.append("No open ports detected")

        lines.extend([f"\n{sep}", "ANALYSIS & INSIGHTS", sep])

        if insights:
            lines.append(f"\nSummary: {insights.get('summary', 'N/A')}")
            lines.append(f"Risk Level: {insights.get('risk_level', 'N/A').upper()}")

            if insights.get("insights"):
                lines.append("\nKey Findings:")
                for item in insights["insights"]:
                    lines.append(f"  - {item}")

            if insights.get("recommendations"):
                lines.append("\nRecommendations:")
                for recommendation in insights["recommendations"]:
                    lines.append(f"  - {recommendation}")

        lines.extend([f"\n{sep}", "END OF REPORT", sep])
        return "\n".join(lines)

    def generate_json_report(
        self,
        target: str,
        mode: str,
        tool: str,
        results: List[ScanResult],
        insights: Dict[str, Any],
        config: Dict = None,
    ) -> str:
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
                **(config or {}),
            },
            "results": ResultsParser.to_dict_list(results),
            "insights": insights,
        }
        return json.dumps(data, indent=2)

    def generate_csv_report(self, results: List[ScanResult]) -> str:
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Port", "Service", "State", "Version"])

        for result in sorted(results, key=lambda item: item.port):
            writer.writerow([result.port, result.service, result.state, result.version or ""])

        return output.getvalue()

    def save_report(self, filename: str, content: str, format: str = "txt"):
        try:
            directory = os.path.dirname(filename)
            if directory:
                os.makedirs(directory, exist_ok=True)

            with open(filename, "w", encoding="utf-8") as file_handle:
                file_handle.write(content)

            logger.info(f"Report saved: {filename}")
            return True, f"Report saved to {filename}"
        except Exception as exc:
            logger.error(f"Save failed: {exc}")
            return False, str(exc)

    def generate_filename(self, target: str, format: str = "txt") -> str:
        safe_target = target.replace(".", "_")
        timestamp = self.timestamp.strftime("%Y%m%d_%H%M%S")
        return os.path.join(
            platform_detector.get_reports_directory(),
            f"{safe_target}_{timestamp}.{format}",
        )
