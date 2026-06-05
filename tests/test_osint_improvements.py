#!/usr/bin/env python3
"""
Test script to verify OSINT improvements functionality.
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_imports():
    """Test that all new modules can be imported successfully."""
    try:
        # Test recon_store
        from clearwing.data.database.recon_store import ReconStore, ReconResult
        print("✓ recon_store import successful")
        
        # Test osint_workflow
        from clearwing.workflows.osint_workflow import run_passive_subdomain_recon
        print("✓ osint_workflow import successful")
        
        # Test output_parsers
        from clearwing.utils.output_parsers import parse_github_json, parse_wayback_json
        print("✓ output_parsers import successful")
        
        # Test correlation
        from clearwing.intel.correlation import IntelCorrelator, correlate_osint_findings
        print("✓ correlation import successful")
        
        # Test native tools
        from clearwing.native.shodan_tools import query_shodan, parse_shodan_results
        print("✓ shodan_tools import successful")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_recon_store():
    """Test basic ReconStore functionality."""
    try:
        from clearwing.data.database.recon_store import ReconStore, ReconResult
        from datetime import datetime
        
        # Create a test store
        store = ReconStore(":memory:")  # Use in-memory database for testing
        
        # Create a test result
        result = ReconResult(
            tool_name="test_tool",
            target="example.com",
            result_type="subdomain",
            data={"subdomains": ["test.example.com"]},
            timestamp=datetime.now().isoformat()
        )
        
        # Store the result
        row_id = store.store_result(result)
        print(f"✓ ReconStore storage successful (row_id: {row_id})")
        
        # Retrieve results
        results = store.get_results_by_target("example.com")
        if len(results) > 0:
            print("✓ ReconStore retrieval successful")
        else:
            print("✗ ReconStore retrieval failed")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ ReconStore test failed: {e}")
        return False

def test_parsers():
    """Test parser functionality."""
    try:
        from clearwing.utils.output_parsers import parse_assetfinder_output, parse_findomain_output
        
        # Test assetfinder parser
        assetfinder_output = "sub1.example.com\nsub2.example.com\nsub3.example.com"
        parsed = parse_assetfinder_output(assetfinder_output)
        if len(parsed.get('subdomains', [])) == 3:
            print("✓ Assetfinder parser successful")
        else:
            print("✗ Assetfinder parser failed")
            return False
            
        # Test findomain parser
        findomain_output = "sub1.example.com,192.168.1.1,200\nsub2.example.com,192.168.1.2,200"
        parsed = parse_findomain_output(findomain_output)
        if len(parsed.get('subdomains', [])) == 2:
            print("✓ Findomain parser successful")
        else:
            print("✗ Findomain parser failed")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ Parser test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing OSINT improvements...")
    print("=" * 40)
    
    # Test imports
    if not test_imports():
        return 1
        
    # Test ReconStore
    if not test_recon_store():
        return 1
        
    # Test parsers
    if not test_parsers():
        return 1
        
    print("=" * 40)
    print("All tests passed! ✓")
    return 0

if __name__ == "__main__":
    sys.exit(main())