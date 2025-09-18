# pro_log_scanner.py
import re
import sys
import geoip2.database
import geoip2.errors

# Initialize the GeoIP reader globally, before any functions
try:
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except geoip2.errors.AddressNotFoundError:
    print("WARNING:  GeoLite2-City.mmdb file not found. IP geolocation will be unavailable.")
    reader = None

def get_location(ip_address):
    """Looks up the country and city for a given IP address."""
    if reader is None:
        return "N/A", "N/A"
    try:
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        return country, city
    except geoip2.errors.AddressNotFoundError:
        return "Unknown", "Unknown"
    except Exception as e:
        print(f"Error looking up IP {ip_address}: {e}")
        return "Unknown", "Unknown"


# Patterns to detect
patterns = {
    "Failed login": re.compile(r"Failed password for", re.IGNORECASE),
    "Error": re.compile(r"ERROR", re.IGNORECASE),
    "Root activity": re.compile(r"\broot\b", re.IGNORECASE),
    "Timestamp": re.compile(r"\b\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", re.IGNORECASE),
    "IP Address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE),
    "SQL Injection": re.compile(r"\b(select|union|update|delete)\b.*?(from|where|having|into)", re.IGNORECASE),
    "Directory Traversal": re.compile(r"\.\.[\\/]", re.IGNORECASE),
    "Command Injection": re.compile(r"(\s(&|\||;)\s|`|eval\(|exec\()", re.IGNORECASE),
    "Remote Code Execution": re.compile(r"(\$|`|\||;|\t|'|\")*?(sh|bash|nc|wget|curl|php|perl|python|java|cat|echo|env|id|pwd|whoami)\b", re.IGNORECASE),
    "Command Shell": re.compile(r"xp_cmdshell", re.IGNORECASE),
    "Cross-Site Scripting": re.compile(r"<script>|javascript:|on\w+=|%3cscript", re.IGNORECASE),
    "Command Line Obfuscation": re.compile(r"echo\s.*\|\s*(sh|bash)|base64\s+-d|\$\(\w\)", re.IGNORECASE),
    "Local File Inclusion & Remote File Inclusion": re.compile(r"(etc/passwd|/proc/self/environ|wp-config.php|file=http)", re.IGNORECASE)

}

# Colors for terminal
colors = {
    "Failed login": "\033[33m",       # Yellow
    "Error": "\033[31m",              # Red
    "Root activity": "\033[35m",      # Magenta
    "SQL Injection": "\033[34m",      # Blue
    "Command Injection": "\033[36m",  # Cyan
    "Directory Traversal":"\033[38;5;208m",      #True Orange
    "Remote Code Execution": "\033[38;5;22m",    #Dark Green
    "Command Shell": "\033[38;5;178m",           #Gold
    "Cross-Site Scripting": "\033[38;5;55m",     #Violet
    "Command Line Obfuscation": "\033[38;5;30m", #Teal
    "Local File Inclusion & Remote File Inclusion": "\033[38;5;160m" #Crimson
}
reset_color = "\033[0m"

def scan_log(file_path, alert_file="alerts.txt"):
    counts = {name: 0 for name in patterns}

    try:
        with open(file_path, 'r') as file, open(alert_file,'a') as alerts:
            for line in file:
                line_clean = line.strip()

                # Find IP addresses in the line
                ip_match = patterns["IP Address"].search(line)
                ip = None
                if ip_match:
                   ip = ip_match.group(0)

                # Color timestamps and IP addresses
                line_clean = re.sub(patterns["Timestamp"], lambda m: f"\033[36m{m.group(0)}{reset_color}", line_clean)
                line_clean = re.sub(patterns["IP Address"], lambda m: f"\033[32m{m.group(0)}{reset_color}", line_clean)

                for name, pattern in patterns.items():
                    if pattern.search(line):
                        counts[name] += 1
                        color = colors.get(name, "")

                        #Get location before modifying the line with color codes 
                        alert_line = f"[ALERT - {name}]"
                        #Only perform lookup ifi an IP was found
                        if ip:
                             country, city = get_location(ip)
                             alert_line += f"from {city}, {country} | "

                        alert_line += line_clean

                        print(f"{color}{alert_line}{reset_color}")
                        alerts.write(alert_line + "\n")
    except FileNotFoundError:
        print(f"\033[31m[ERROR] File not found: {file_path}{reset_color}")

    # Per-file summary
    print("\n--- Summary ---")
    for name, count in counts.items():
        print(f"{name}: {count} alert(s)")

    return counts

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pro_log_scanner.py <log_file1> [<log_file2> ...]")
        sys.exit(1)

    log_files = sys.argv[1:]
    combined_counts = {name: 0 for name in patterns}

    for log_file in log_files:
        print(f"\nScanning {log_file}...\n")
        file_counts = scan_log(log_file)
        # Update combined totals
        for key in combined_counts:
            combined_counts[key] += file_counts.get(key, 0)

    # Combined summary across all files
    print("\n=== Combined Summary Across All Files ===")
    for name, count in combined_counts.items():
        print(f"{name}: {count} alert(s)")

