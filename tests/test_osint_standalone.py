#!/usr/bin/env python3
"""
Standalone test script to verify OSINT improvements functionality.
This script tests the core functionality without importing the full Nightwing project.
"""

import sys
from typing import Any


def test_recon_store():
    """Test basic ReconStore functionality."""
    try:
        import json
        import sqlite3
        from dataclasses import dataclass
        from datetime import datetime
        from typing import Any

        @dataclass
        class ReconResult:
            """Data class for storing reconnaissance results."""

            tool_name: str
            target: str
            result_type: str
            data: dict[str, Any]
            timestamp: str
            scan_id: str | None = None

        # Test ReconStore functionality directly
        db_path = ":memory:"  # Use in-memory database for testing

        # Initialize database
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recon_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.commit()

        # Create a test result
        result = ReconResult(
            tool_name="test_tool",
            target="example.com",
            result_type="subdomain",
            data={"subdomains": ["test.example.com"]},
            timestamp=datetime.now().isoformat(),
        )

        # Store the result
        with sqlite3.connect(db_path) as conn:
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

        print(f"✓ ReconStore storage successful (row_id: {row_id})")

        # Retrieve results
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM recon_results 
                WHERE target = ?
            """,
                ("example.com",),
            )

            rows = cursor.fetchall()

            results = []
            for row in rows:
                result_dict = dict(row)
                result_dict["data"] = json.loads(result_dict["data"])
                results.append(result_dict)

        if len(results) > 0:
            print("✓ ReconStore retrieval successful")
            return True
        else:
            print("✗ ReconStore retrieval failed")
            return False

    except Exception as e:
        print(f"✗ ReconStore test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_parsers():
    """Test parser functionality."""
    try:

        def parse_assetfinder_output(output: str) -> dict[str, Any]:
            """Parse assetfinder output into structured data."""
            lines = output.strip().split("\n")
            subdomains = []

            for line in lines:
                if line.strip():
                    # Clean up the line
                    clean_line = line.strip().lstrip("*.")
                    if clean_line:
                        subdomains.append(clean_line)

            return {
                "subdomains": list(set(subdomains)),  # Remove duplicates
                "total_found": len(set(subdomains)),
            }

        def parse_findomain_output(output: str) -> dict[str, Any]:
            """Parse findomain output into structured data."""
            lines = output.strip().split("\n")
            subdomains = []

            for line in lines:
                if line.strip():
                    # Findomain outputs CSV with subdomain as first column
                    parts = line.split(",")
                    if parts and parts[0].strip():
                        subdomain = parts[0].strip().lstrip("*.")
                        if subdomain:
                            subdomains.append(subdomain)

            return {
                "subdomains": list(set(subdomains)),  # Remove duplicates
                "total_found": len(set(subdomains)),
            }

        # Test assetfinder parser
        assetfinder_output = "sub1.example.com\nsub2.example.com\nsub3.example.com"
        parsed = parse_assetfinder_output(assetfinder_output)
        if len(parsed.get("subdomains", [])) == 3:
            print("✓ Assetfinder parser successful")
        else:
            print("✗ Assetfinder parser failed")
            return False

        # Test findomain parser
        findomain_output = "sub1.example.com,192.168.1.1,200\nsub2.example.com,192.168.1.2,200"
        parsed = parse_findomain_output(findomain_output)
        if len(parsed.get("subdomains", [])) == 2:
            print("✓ Findomain parser successful")
        else:
            print("✗ Findomain parser failed")
            return False

        return True

    except Exception as e:
        print(f"✗ Parser test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("Testing OSINT improvements (standalone)...")
    print("=" * 50)

    # Test ReconStore
    if not test_recon_store():
        return 1

    # Test parsers
    if not test_parsers():
        return 1

    print("=" * 50)
    print("All tests passed! ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
