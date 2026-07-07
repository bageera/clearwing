"""Reconnaissance Data Storage Module.

This module provides classes for storing reconnaissance results in both
SQLite database and JSONL file formats, plus aggregation and reporting capabilities.
"""

import json
import logging
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReconResult:
    """Data class for storing reconnaissance results."""

    tool_name: str
    target: str
    result_type: str  # 'subdomain', 'ip', 'email', 'certificate', 'vulnerability'
    data: dict[str, Any]
    timestamp: str
    scan_id: str | None = None


class ReconStore:
    """Class for storing reconnaissance results in SQLite and JSONL formats."""

    def __init__(self, db_path: str = "recon_results.db", jsonl_path: str = "recon_results.jsonl"):
        """Initialize the ReconStore.

        Args:
            db_path: Path to SQLite database file
            jsonl_path: Path to JSONL file for backup/export
        """
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the SQLite database with required tables."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create recon_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recon_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result_type TEXT NOT NULL,
                    data TEXT NOT NULL,  # JSON string
                    timestamp TEXT NOT NULL
                )
            """)

            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tool_target 
                ON recon_results(tool_name, target)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_result_type 
                ON recon_results(result_type)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON recon_results(timestamp)
            """)

            conn.commit()

    def store_result(self, result: ReconResult) -> int:
        """Store a reconnaissance result.

        Args:
            result: ReconResult object to store

        Returns:
            Row ID of inserted record
        """
        try:
            # Store in SQLite
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO recon_results 
                    (scan_id, tool_name, target, result_type, data, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        result.scan_id,
                        result.tool_name,
                        result.target,
                        result.result_type,
                        json.dumps(result.data),
                        result.timestamp,
                    ),
                )
                row_id = cursor.lastrowid
                conn.commit()

            # Store in JSONL
            self._append_to_jsonl(result)

            logger.info(f"Stored result from {result.tool_name} for target {result.target}")
            return row_id

        except Exception as e:
            logger.error(f"Failed to store result: {str(e)}")
            raise

    def _append_to_jsonl(self, result: ReconResult) -> None:
        """Append a result to the JSONL file."""
        Path(self.jsonl_path).parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary and write as JSON line
        result_dict = {
            "id": None,  # Will be set when reading back
            "scan_id": result.scan_id,
            "tool_name": result.tool_name,
            "target": result.target,
            "result_type": result.result_type,
            "data": result.data,
            "timestamp": result.timestamp,
        }

        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(result_dict) + "\n")

    def get_results_by_tool(
        self, tool_name: str, target: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve results by tool name.

        Args:
            tool_name: Name of the tool to filter by
            target: Optional target to filter by

        Returns:
            List of result dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if target:
                cursor.execute(
                    """
                    SELECT * FROM recon_results 
                    WHERE tool_name = ? AND target = ?
                    ORDER BY timestamp DESC
                """,
                    (tool_name, target),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM recon_results 
                    WHERE tool_name = ?
                    ORDER BY timestamp DESC
                """,
                    (tool_name,),
                )

            rows = cursor.fetchall()

            results = []
            for row in rows:
                result = dict(row)
                # Parse JSON data back to dict
                result["data"] = json.loads(result["data"])
                results.append(result)

            return results

    def get_results_by_target(self, target: str) -> list[dict[str, Any]]:
        """Retrieve all results for a specific target.

        Args:
            target: Target to filter by

        Returns:
            List of result dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM recon_results 
                WHERE target = ?
                ORDER BY timestamp DESC, tool_name
            """,
                (target,),
            )

            rows = cursor.fetchall()

            results = []
            for row in rows:
                result = dict(row)
                # Parse JSON data back to dict
                result["data"] = json.loads(result["data"])
                results.append(result)

            return results

    def get_results_by_type(self, result_type: str) -> list[dict[str, Any]]:
        """Retrieve all results of a specific type.

        Args:
            result_type: Type of results to filter by

        Returns:
            List of result dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM recon_results 
                WHERE result_type = ?
                ORDER BY timestamp DESC, target
            """,
                (result_type,),
            )

            rows = cursor.fetchall()

            results = []
            for row in rows:
                result = dict(row)
                # Parse JSON data back to dict
                result["data"] = json.loads(result["data"])
                results.append(result)

            return results

    def export_to_jsonl(self, output_path: str) -> None:
        """Export all results to a JSONL file.

        Args:
            output_path: Path to export file
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM recon_results ORDER BY timestamp")
            rows = cursor.fetchall()

            with open(output_path, "w") as f:
                for row in rows:
                    result = dict(row)
                    # Parse JSON data back to dict for export
                    result["data"] = json.loads(result["data"])
                    f.write(json.dumps(result) + "\n")

        logger.info(f"Exported {len(rows)} results to {output_path}")

    def import_from_jsonl(self, input_path: str) -> int:
        """Import results from a JSONL file.

        Args:
            input_path: Path to import file

        Returns:
            Number of records imported
        """
        count = 0
        with open(input_path) as f:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                for line in f:
                    if line.strip():
                        result_data = json.loads(line.strip())

                        cursor.execute(
                            """
                            INSERT INTO recon_results 
                            (scan_id, tool_name, target, result_type, data, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """,
                            (
                                result_data["scan_id"],
                                result_data["tool_name"],
                                result_data["target"],
                                result_data["result_type"],
                                json.dumps(result_data["data"]),
                                result_data["timestamp"],
                            ),
                        )

                        # Also append to our JSONL file
                        with open(self.jsonl_path, "a") as out_f:
                            out_f.write(line)

                        count += 1

                conn.commit()

        logger.info(f"Imported {count} results from {input_path}")
        return count

    def get_combined_recon_results(self, target: str) -> dict[str, Any]:
        """Get consolidated view of all recon results for a target.

        Args:
            target: Target domain to get consolidated results for

        Returns:
            Dictionary with combined reconnaissance results
        """
        results = self.get_results_by_target(target)

        # Initialize collections
        subdomains: set[str] = set()
        ips: set[str] = set()
        emails: set[str] = set()
        urls: set[str] = set()
        certificates: list[dict] = []
        tool_usage: dict[str, int] = {}

        # Process all results
        for result in results:
            tool_name = result["tool_name"]
            result_type = result["result_type"]
            data = result["data"]

            # Count tool usage
            tool_usage[tool_name] = tool_usage.get(tool_name, 0) + 1

            # Extract data based on type
            if result_type == "subdomain":
                if "subdomains" in data:
                    subdomains.update(data["subdomains"])
                elif "subdomain" in data:
                    subdomains.add(data["subdomain"])

            elif result_type == "ip":
                if "ips" in data:
                    ips.update(data["ips"])
                elif "ip" in data:
                    ips.add(data["ip"])

            elif result_type == "email":
                if "emails" in data:
                    emails.update(data["emails"])
                elif "email" in data:
                    emails.add(data["email"])

            elif result_type == "url":
                if "urls" in data:
                    urls.update(data["urls"])
                elif "url" in data:
                    urls.add(data["url"])

            elif result_type == "certificate":
                certificates.append(data)

        return {
            "target": target,
            "summary": {
                "total_subdomains": len(subdomains),
                "total_ips": len(ips),
                "total_emails": len(emails),
                "total_urls": len(urls),
                "total_certificates": len(certificates),
                "tools_used": tool_usage,
            },
            "findings": {
                "subdomains": sorted(list(subdomains)),
                "ips": sorted(list(ips)),
                "emails": sorted(list(emails)),
                "urls": sorted(list(urls)),
                "certificates": certificates,
            },
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_results_processed": len(results),
            },
        }

    def generate_recon_summary(self, target: str) -> dict[str, Any]:
        """Generate a detailed summary report of recon activities.

        Args:
            target: Target domain to generate summary for

        Returns:
            Dictionary with summary statistics and insights
        """
        combined_results = self.get_combined_recon_results(target)

        # Calculate additional metrics
        subdomains = combined_results["findings"]["subdomains"]
        ips = combined_results["findings"]["ips"]

        # Subdomain analysis
        subdomain_depths = [len(sub.split(".")) for sub in subdomains]
        avg_depth = sum(subdomain_depths) / len(subdomain_depths) if subdomain_depths else 0

        # IP analysis
        ip_classes = {}
        for ip in ips:
            if "." in ip:  # IPv4
                first_octet = ip.split(".")[0]
                ip_classes[f"Class {first_octet}"] = ip_classes.get(f"Class {first_octet}", 0) + 1

        return {
            "target": target,
            "overview": combined_results["summary"],
            "analysis": {
                "subdomain_analysis": {
                    "average_depth": round(avg_depth, 2),
                    "common_prefixes": self._get_common_prefixes(subdomains),
                    "potential_wildcards": self._identify_wildcard_candidates(subdomains),
                },
                "ip_analysis": {
                    "distribution": ip_classes,
                    "geographic_spread": "Analysis requires external geoip lookup",
                },
                "temporal_analysis": self._get_temporal_insights(target),
            },
            "recommendations": self._generate_recommendations(combined_results),
        }

    def _get_common_prefixes(self, subdomains: list[str], min_length: int = 3) -> list[str]:
        """Identify common prefixes in subdomains."""
        prefixes = Counter()
        for sub in subdomains:
            parts = sub.split(".")
            # Add prefixes of increasing length
            for i in range(len(parts)):
                prefix = ".".join(parts[i:])
                if len(prefix) >= min_length:
                    prefixes[prefix] += 1

        # Return top 10 most common prefixes that appear more than once
        return [prefix for prefix, count in prefixes.most_common(10) if count > 1]

    def _identify_wildcard_candidates(self, subdomains: list[str]) -> list[str]:
        """Identify potential wildcard subdomains based on naming patterns."""
        candidates = []
        for sub in subdomains:
            # Look for common wildcard patterns
            if any(pattern in sub.lower() for pattern in ["dev", "staging", "test", "uat"]):
                candidates.append(sub)
        return candidates

    def _get_temporal_insights(self, target: str) -> dict[str, Any]:
        """Get insights based on timing of discoveries."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT tool_name, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                FROM recon_results 
                WHERE target = ?
                GROUP BY tool_name
                ORDER BY first_seen
            """,
                (target,),
            )

            rows = cursor.fetchall()

            timeline = []
            for row in rows:
                timeline.append(
                    {
                        "tool": row["tool_name"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    }
                )

            return {
                "discovery_timeline": timeline,
                "earliest_discovery": min([r["first_seen"] for r in timeline])
                if timeline
                else None,
                "latest_discovery": max([r["last_seen"] for r in timeline]) if timeline else None,
            }

    def _generate_recommendations(self, combined_results: dict[str, Any]) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        summary = combined_results["summary"]
        combined_results["findings"]

        # Subdomain recommendations
        if summary["total_subdomains"] > 100:
            recommendations.append(
                "High number of subdomains discovered. Consider targeted scanning."
            )

        if summary["total_subdomains"] > summary["total_ips"]:
            recommendations.append(
                "More subdomains than IPs found. Consider DNS enumeration techniques."
            )

        # Email recommendations
        if summary["total_emails"] > 0:
            recommendations.append(
                "Email addresses discovered. Consider social engineering validation."
            )

        # URL recommendations
        if summary["total_urls"] > 50:
            recommendations.append("Numerous URLs discovered. Prioritize web application testing.")

        # Coverage recommendations
        if summary["total_subdomains"] == 0 and summary["total_ips"] == 0:
            recommendations.append(
                "Limited discovery. Consider alternative enumeration techniques."
            )

        return recommendations
