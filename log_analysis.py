import csv
from collections import defaultdict, Counter
import re

# Configuration
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_PATTERN = r"401|Invalid credentials"

def process_log_file(file_path):
    """
    Processes the log file and extracts IP requests, endpoint accesses, and failed login attempts.
    """
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_login_attempts = defaultdict(int)
    
    ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE)\s(\/[^\s]*)'

    with open(file_path, "r") as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip_requests[ip_match.group(1)] += 1
            
            # Extract endpoint
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint_access[endpoint_match.group(1)] += 1
            
            # Check for failed login attempts
            if re.search(FAILED_LOGIN_PATTERN, line) and ip_match:
                failed_login_attempts[ip_match.group(1)] += 1
    
    return ip_requests, endpoint_access, failed_login_attempts
def generate_output(ip_requests, endpoint_access, failed_login_attempts, threshold):
    """
    Prepares output data for displaying and saving to CSV.
    """
    # Sort IP requests by count
    ip_request_data = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    
    # Find the most accessed endpoint
    most_accessed_endpoint, access_count = max(endpoint_access.items(), key=lambda x: x[1], default=("None", 0))
    most_accessed = f"{most_accessed_endpoint} (Accessed {access_count} times)"
    
    # Filter failed login attempts exceeding the threshold
    suspicious_activity = [(ip, count) for ip, count in failed_login_attempts.items() if count > threshold]
    
    return ip_request_data, most_accessed, suspicious_activity


def save_to_csv(output_data, file_path):
    """
    Saves analysis results to a CSV file.
    """
    ip_request_data, most_accessed, suspicious_activity = output_data

    with open(file_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write IP Requests
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_request_data)

        writer.writerow([])  # Blank line for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        endpoint, access_count = most_accessed.split(" (Accessed ")
        access_count = access_count.replace(" times)", "")  # Clean up "times" suffix
        writer.writerow([endpoint, access_count])

        writer.writerow([])  # Blank line for separation

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)


def main():
    # Step 1: Process the log file
    ip_requests, endpoint_access, failed_login_attempts = process_log_file(LOG_FILE)

    # Step 2: Generate output data
    output_data = generate_output(ip_requests, endpoint_access, failed_login_attempts, FAILED_LOGIN_THRESHOLD)

    # Step 3: Display results
    ip_request_data, most_accessed, suspicious_activity = output_data
    
    print("\nRequests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in ip_request_data:
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(most_accessed)
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity:
        print(f"{ip:<20} {count}")

    # Step 4: Save results to CSV
    save_to_csv(output_data, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
