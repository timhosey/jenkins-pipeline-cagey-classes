import requests
import re
import os

TARGET_EXTENSIONS = [".groovy", "Jenkinsfile", ".Jenkinsfile"]

# Dangerous patterns for pipelines to run
DANGER_PATTERNS = {
    '@NonCPS': r'@NonCPS',
    'JsonSlurper': r'new\s+JsonSlurper\(\)',
    'File usage': r'new\s+File\(',
    'InputStream': r'InputStream',
    'Socket': r'Socket',
}

# This should detect inadvertently declared global vars in a pipeline
GLOBAL_VAR_PATTERN = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[^=]', re.MULTILINE)

def detect_global_vars(content):
    content_cleaned = re.sub(r'//.*', '', content)
    content_cleaned = re.sub(r'(?s)pipeline\s*{.*?}', '', content_cleaned)

    findings = []
    for match in GLOBAL_VAR_PATTERN.finditer(content_cleaned):
        var_name = match.group(1)
        if not re.search(r'\b(def|String|int|boolean|float|double|var)\s+' + re.escape(var_name), content):
            findings.append(var_name)
    return findings

def scan_content(content):
    findings = []
    for name, pattern in DANGER_PATTERNS.items():
        if re.search(pattern, content):
            findings.append(name)
    global_issues = detect_global_vars(content)
    if global_issues:
        findings.append(f"Global vars: {', '.join(global_issues)}")
    return findings

def scan_github_repo(owner, repo, path=""):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    response = requests.get(url)
    response.raise_for_status()
    items = response.json()

    for item in items:
        if item['type'] == 'file' and (os.path.splitext(item['name'])[1] in TARGET_EXTENSIONS or item['name'] in TARGET_EXTENSIONS):
            raw_url = item['download_url']
            content = requests.get(raw_url).text
            issues = scan_content(content)
            if issues:
                print(f"☠️ {item['path']} -> {', '.join(issues)}")
        elif item['type'] == 'dir':
            scan_github_repo(owner, repo, item['path'])

# Example usage:
scan_github_repo("timhosey", "jenkinsfiles")