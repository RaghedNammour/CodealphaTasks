import sys
import os
import subprocess
import json

def run_bandit_scan(target_file):
    """Run Bandit security scan on a single file using the CLI."""
    command = ["bandit", "-f", "json", target_file]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Error running Bandit: {result.stderr}")
        return {}

    if result.stdout:
        print(f"Bandit Output:\n{result.stdout}")  # Show Bandit output for debug
    
    try:
        # Parse the output as JSON
        output_json = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("❌ Error: Could not parse Bandit output as JSON.")
        return {}
    
    return output_json

def analyze_results(results):
    """Analyze Bandit scan results and provide recommendations."""
    issues = results.get("results", [])

    if not issues:
        print("✅ No security issues found. Your code looks good!")
        return

    print("🚨 Security issues detected:\n")
    for issue in issues:
        print(f"- 📂 File: {issue['filename']}")
        print(f"  ❌ Issue: {issue['test_name']} ({issue['test_id']})")
        print(f"  ⚠️ Severity: {issue['issue_severity']}, Confidence: {issue['issue_confidence']}")
        print(f"  🔎 Description: {issue['issue_text']}")
        print(f"  📌 Line: {issue['line_number']}")
        print("  ----------------------------------")

    print("\n📢 Recommendations:")
    print("- 🛡️ Follow OWASP secure coding guidelines.")
    print("- 🔑 Avoid hardcoded credentials and API keys.")
    print("- 🧹 Sanitize user input to prevent injections.")
    print("- 📦 Keep dependencies updated for security patches.")
    print("- 🏗️ Use virtual environments for better package management.")
    print("- 🛠️ Consider additional security tools like linters and dependency checkers.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python \"Secure Code Review.py\" \"script for testing.py\"")
        sys.exit(1)

    target_file = sys.argv[1]
    if not os.path.exists(target_file):
        print("❌ Error: Target file does not exist.")
        sys.exit(1)

    print(f"🔍 Scanning {target_file} for security vulnerabilities...")
    results = run_bandit_scan(target_file)
    if results:
        analyze_results(results)


if __name__ == "__main__":
    main()
