import os
import sys
import httpx
import subprocess

SONAR_TOKEN = "squ_d7721e5bb7a3ae4ee9b42fd5d876dfbdd45c6f36"
SONAR_URL = "http://localhost:9000"
PHOENIX_URL = "http://localhost:8012"
PROJECT_ROOT = "/home/grzegorz/cloud/dreamsoft_factory/backend"

def run_tests():
    """Runs PHPUnit tests in the docker container and returns True if they pass."""
    try:
        res = subprocess.run(
            ["docker", "exec", "-i", "backend", "./vendor/bin/phpunit"],
            capture_output=True,
            text=True
        )
        return "OK" in res.stdout and "FAILURES!" not in res.stdout
    except Exception as e:
        print(f"Error running tests: {e}")
        return False

def get_sonar_issues():
    """Fetches unresolved high-priority bugs from SonarQube."""
    url = f"{SONAR_URL}/api/issues/search"
    params = {
        "componentKeys": "backend",
        "resolved": "false",
        "types": "BUG",
        "severities": "CRITICAL,BLOCKER,MAJOR",
        "ps": 100
    }
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    
    resp = httpx.get(url, params=params, headers=headers)
    if resp.status_code != 200:
        print(f"Failed to fetch Sonar issues: {resp.text}")
        return []
    return resp.json().get("issues", [])

def group_issues_by_file(issues):
    grouped = {}
    for issue in issues:
        comp = issue["component"]
        # Sonar format is "backend:path/to/file.php"
        if ":" in comp:
            file_path = comp.split(":", 1)[1]
        else:
            file_path = comp
        
        # Resolve to host path
        host_path = os.path.join(PROJECT_ROOT, file_path)
        if not os.path.exists(host_path):
            continue
            
        if host_path not in grouped:
            grouped[host_path] = []
        grouped[host_path].append(issue)
    return grouped

def main():
    print("Fetching active issues from SonarQube...")
    issues = get_sonar_issues()
    if not issues:
        print("No active high-priority bugs found!")
        return
        
    grouped = group_issues_by_file(issues)
    print(f"Found issues in {len(grouped)} files.")
    
    for file_path, file_issues in grouped.items():
        print(f"\nProcessing {file_path} ({len(file_issues)} issues)...")
        
        # 1. Read file content
        with open(file_path, "r", encoding="utf-8") as f:
            original_code = f.read()
            
        # 2. Accumulate issues description
        reasons = []
        for issue in file_issues:
            reasons.append(f"Line {issue.get('line')}: {issue.get('message')}")
        reason_str = "\n".join(reasons)
        
        # 3. Call RAE-Phoenix for repair
        print("Sending to RAE-Phoenix...")
        payload = {
            "project": "backend",
            "code": original_code,
            "reason": f"Fix the following bugs:\n{reason_str}",
            "file_path": os.path.relpath(file_path, PROJECT_ROOT)
        }
        
        try:
            resp = httpx.post(f"{PHOENIX_URL}/v2/phoenix/repair", json=payload, timeout=600.0)
            if resp.status_code != 200:
                print(f"Phoenix request failed: {resp.text}")
                continue
                
            result = resp.json()
            if result.get("status") == "SUCCESS":
                fixed_code = result.get("code")
                
                # 4. Write fixed code to file
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(fixed_code)
                    
                # 5. Run regression tests
                print("Running regression tests...")
                if run_tests():
                    print("SUCCESS: Tests passed! Fix applied.")
                else:
                    print("FAILURE: Tests failed. Rolling back changes.")
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(original_code)
            else:
                print(f"Phoenix repair failed: {result.get('reason')}")
        except Exception as e:
            print(f"Error processing file: {e}")
            # Rollback just in case
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original_code)

if __name__ == "__main__":
    main()
