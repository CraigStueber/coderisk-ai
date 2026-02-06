"""
Tests for A06: Vulnerable & Outdated Components detector (v0.1)
"""
from pathlib import Path
from coderisk_ai.detectors.python.a06_vulnerable_outdated_components import detect_vulnerable_outdated_components


def test_unpinned_requirements_txt():
    """Test detection of unpinned dependencies in requirements.txt"""
    source = """# Test requirements.txt
requests
urllib3>=1.26.0
Flask~=2.0.0
numpy==1.21.0
click
"""
    findings = detect_vulnerable_outdated_components(source, "requirements.txt")
    
    # Should detect unpinned ones but not numpy==1.21.0
    unpinned_findings = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.UNPINNED"]
    assert len(unpinned_findings) > 0, "Should detect unpinned dependencies"
    
    # Check that we have instances
    for finding in unpinned_findings:
        assert "instances" in finding
        assert len(finding["instances"]) > 0
        assert finding["category"] == "A06_vulnerable_outdated_components"
        assert "rule_id" in finding


def test_deprecated_packages():
    """Test detection of deprecated packages"""
    source = """# Test requirements with deprecated packages
pycrypto==2.6.1
oauth2>=1.9.0
nose==1.3.7
requests==2.28.0
"""
    findings = detect_vulnerable_outdated_components(source, "requirements.txt")
    
    # Should detect deprecated packages
    deprecated_findings = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.DEPRECATED"]
    assert len(deprecated_findings) > 0, "Should detect deprecated packages"
    
    # Verify deprecated packages are detected
    found_packages = set()
    for finding in deprecated_findings:
        for instance in finding["instances"]:
            snippet = instance["snippet"].lower()
            if "pycrypto" in snippet:
                found_packages.add("pycrypto")
            if "oauth2" in snippet:
                found_packages.add("oauth2")
            if "nose" in snippet:
                found_packages.add("nose")
    
    assert "pycrypto" in found_packages, "Should detect pycrypto"
    assert "oauth2" in found_packages, "Should detect oauth2"
    assert "nose" in found_packages, "Should detect nose"


def test_pinned_dependencies_not_flagged():
    """Test that properly pinned dependencies are NOT flagged"""
    source = """# Properly pinned requirements
requests==2.28.1
urllib3==1.26.12
Flask==2.2.2
"""
    findings = detect_vulnerable_outdated_components(source, "requirements.txt")
    
    # Should have no unpinned findings
    unpinned_findings = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.UNPINNED"]
    assert len(unpinned_findings) == 0, "Pinned dependencies should not be flagged"


def test_pyproject_toml_unpinned():
    """Test detection of unpinned dependencies in pyproject.toml"""
    source = """[tool.poetry.dependencies]
python = "^3.9"
requests = "*"
flask = "^2.0.0"
numpy = "1.21.0"
"""
    findings = detect_vulnerable_outdated_components(source, "pyproject.toml")
    
    # Should detect unpinned ones
    unpinned_findings = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.UNPINNED"]
    assert len(unpinned_findings) > 0, "Should detect unpinned dependencies in pyproject.toml"
    
    # Check category and schema
    for finding in unpinned_findings:
        assert finding["category"] == "A06_vulnerable_outdated_components"
        assert "instances" in finding
        assert "references" in finding


def test_pyproject_toml_deprecated():
    """Test detection of deprecated packages in pyproject.toml"""
    source = """[tool.poetry.dependencies]
python = "^3.9"
pycrypto = "^2.6"
requests = "2.28.0"
"""
    findings = detect_vulnerable_outdated_components(source, "pyproject.toml")
    
    # Should detect pycrypto
    deprecated_findings = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.DEPRECATED"]
    assert len(deprecated_findings) > 0, "Should detect deprecated packages in pyproject.toml"


def test_schema_compliance():
    """Test that findings follow the required schema"""
    source = """requests
pycrypto==2.6.1
"""
    findings = detect_vulnerable_outdated_components(source, "requirements.txt")
    
    assert len(findings) > 0, "Should have findings"
    
    for finding in findings:
        # Check required top-level fields
        assert "rule_id" in finding
        assert "id" in finding
        assert "title" in finding
        assert "description" in finding
        assert "category" in finding
        assert finding["category"] == "A06_vulnerable_outdated_components"
        assert "severity" in finding
        assert finding["severity"] in ["critical", "high", "medium", "low", "info"]
        assert "rule_score" in finding
        assert "confidence" in finding
        assert 0.0 <= finding["confidence"] <= 1.0
        assert "exploit_scenario" in finding
        assert "recommended_fix" in finding
        assert "instances" in finding
        assert "references" in finding
        
        # Check instances
        assert len(finding["instances"]) > 0
        for instance in finding["instances"]:
            assert "file" in instance
            assert "line_start" in instance
            assert "line_end" in instance
            assert "snippet" in instance
            assert "explanation" in instance
        
        # Check references include OWASP A06
        assert any(
            ref.get("type") == "OWASP" and "A06" in ref.get("value", "")
            for ref in finding["references"]
        )


def test_deduplication():
    """Test that multiple instances are properly deduplicated into one finding"""
    source = """requests
urllib3>=1.26.0
Flask~=2.0.0
"""
    findings = detect_vulnerable_outdated_components(source, "requirements.txt")
    
    # Should have one finding for A06.DEPENDENCIES.UNPINNED with multiple instances
    unpinned_findings = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.UNPINNED"]
    
    if len(unpinned_findings) > 0:
        # Check that the finding has multiple instances
        finding = unpinned_findings[0]
        assert len(finding["instances"]) >= 3, "Should have multiple instances in one finding"


def test_example_files():
    """Test the example files we created"""
    examples_dir = Path(__file__).parent.parent / "examples"
    
    # Test requirements_unpinned.txt
    unpinned_file = examples_dir / "requirements_unpinned.txt"
    if unpinned_file.exists():
        source = unpinned_file.read_text()
        findings = detect_vulnerable_outdated_components(source, str(unpinned_file))
        unpinned = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.UNPINNED"]
        assert len(unpinned) > 0, "requirements_unpinned.txt should have unpinned findings"
    
    # Test requirements_deprecated.txt
    deprecated_file = examples_dir / "requirements_deprecated.txt"
    if deprecated_file.exists():
        source = deprecated_file.read_text()
        findings = detect_vulnerable_outdated_components(source, str(deprecated_file))
        deprecated = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.DEPRECATED"]
        assert len(deprecated) > 0, "requirements_deprecated.txt should have deprecated findings"
    
    # Test requirements_pinned.txt
    pinned_file = examples_dir / "requirements_pinned.txt"
    if pinned_file.exists():
        source = pinned_file.read_text()
        findings = detect_vulnerable_outdated_components(source, str(pinned_file))
        unpinned = [f for f in findings if f["rule_id"] == "A06.DEPENDENCIES.UNPINNED"]
        assert len(unpinned) == 0, "requirements_pinned.txt should have no unpinned findings"


if __name__ == "__main__":
    # Run tests
    test_unpinned_requirements_txt()
    print("✓ test_unpinned_requirements_txt")
    
    test_deprecated_packages()
    print("✓ test_deprecated_packages")
    
    test_pinned_dependencies_not_flagged()
    print("✓ test_pinned_dependencies_not_flagged")
    
    test_pyproject_toml_unpinned()
    print("✓ test_pyproject_toml_unpinned")
    
    test_pyproject_toml_deprecated()
    print("✓ test_pyproject_toml_deprecated")
    
    test_schema_compliance()
    print("✓ test_schema_compliance")
    
    test_deduplication()
    print("✓ test_deduplication")
    
    test_example_files()
    print("✓ test_example_files")
    
    print("\nAll A06 tests passed! ✓")
