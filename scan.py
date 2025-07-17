import os
import re

# Reuse danger patterns
DANGER_PATTERNS = {
    '@NonCPS': r'@NonCPS',
    'JsonSlurper': r'new\s+JsonSlurper\(\)',
    'File usage': r'new\s+File\(',
    'InputStream': r'InputStream',
    'Socket': r'Socket',
}

# Linter pattern for global var detection (basic)
GLOBAL_VAR_PATTERN = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[^=]', re.MULTILINE)

def detect_global_vars(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Remove comments and pipeline blocks to reduce false positives
    content_cleaned = re.sub(r'//.*', '', content)
    content_cleaned = re.sub(r'(?s)pipeline\s*{.*?}', '', content_cleaned)

    findings = []
    for match in GLOBAL_VAR_PATTERN.finditer(content_cleaned):
        var_name = match.group(1)
        if not re.search(r'\b(def|String|int|boolean|float|double|var)\s+' + re.escape(var_name), content):
            findings.append(var_name)
    return findings

def scan_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    findings = []
    for name, pattern in DANGER_PATTERNS.items():
        if re.search(pattern, content):
            findings.append(name)
    global_issues = detect_global_vars(filepath)
    if global_issues:
        findings.append(f"Global vars: {', '.join(global_issues)}")
    return findings

def scan_repo(root_path):
    for subdir, _, files in os.walk(root_path):
        for file in files:
            if file.endswith(".groovy") or file == "Jenkinsfile":
                full_path = os.path.join(subdir, file)
                issues = scan_file(full_path)
                if issues:
                    print(f"⚠️ {full_path} -> {', '.join(issues)}")

# Example usage
scan_repo('./test-scan')