import re

def analyze_logs(file):
    suspicious = []

    with open(file, 'r') as f:
        logs = f.readlines()

    for line in logs:
        # Detect failed login attempts
        if "failed login" in line.lower():
            suspicious.append(("FAILED LOGIN", line.strip()))

        # Detect multiple IP attempts
        ip_match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
        if ip_match:
            ip = ip_match[0]
            if "error" in line.lower():
                suspicious.append(("SUSPICIOUS IP", ip))

    return suspicious


def generate_report(results):
    print("=== SECURITY REPORT ===")
    for r in results:
        print(f"{r[0]} -> {r[1]}")


if __name__ == "__main__":
    results = analyze_logs("sample_logs.txt")
    generate_report(results)
