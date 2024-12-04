import mmap
import re
import multiprocessing
from collections import defaultdict, Counter

# Regular expression pattern to match failed login attempts with '401' status code
log_pattern = r'(?P<ip_address>\d+\.\d+\.\d+\.\d+) - - \[\S+ \S+\] "POST /login \S+" 401 \d+ "Invalid credentials"'

def process_log_chunk(chunk, ip_failed_login_count, endpoint_counter, ip_request_counter):
    """Process a chunk of the log file and count failed login attempts and other metrics."""
    local_ip_failed_login_count = defaultdict(int)
    local_endpoint_counter = defaultdict(int)
    local_ip_request_counter = defaultdict(int)

    for log in chunk.splitlines():
        # Match failed login attempts
        match = re.search(log_pattern, log)
        if match:
            ip_address = match.group('ip_address')
            local_ip_failed_login_count[ip_address] += 1

        # Extract endpoints
        endpoint = extract_endpoint(log)
        if endpoint:
            local_endpoint_counter[endpoint] += 1

        # Count IP requests
        ip = extract_ip(log)
        if ip:
            local_ip_request_counter[ip] += 1

    # Update the shared dictionaries in a thread-safe way
    for ip, count in local_ip_failed_login_count.items():
        ip_failed_login_count[ip] = ip_failed_login_count.get(ip, 0) + count

    for endpoint, count in local_endpoint_counter.items():
        endpoint_counter[endpoint] = endpoint_counter.get(endpoint, 0) + count

    for ip, count in local_ip_request_counter.items():
        ip_request_counter[ip] = ip_request_counter.get(ip, 0) + count

def extract_endpoint(line):
    """Extract endpoint from the log line."""
    match = re.search(r'"(?:GET|POST|PUT|DELETE)\s(/[\w/-]*)\sHTTP', line)
    if match:
        return match.group(1)
    return None

def extract_ip(line):
    """Extract IP address from the log line."""
    match = re.match(r'^(\S+)', line)
    if match:
        return match.group(1)
    return None

def process_log_file(file_path):
    """Process a large log file using multiprocessing and memory-mapped files."""
    with open(file_path, 'r') as f:
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        chunk_size = 100 * 1024 * 1024  # 100MB per chunk
        num_chunks = len(mmapped_file) // chunk_size + 1

        # Manager for sharing data across processes
        manager = multiprocessing.Manager()
        ip_failed_login_count = manager.dict()
        endpoint_counter = manager.dict()  # Use manager.dict() for endpoint counts
        ip_request_counter = manager.dict()

        # Prepare chunks for parallel processing
        chunks = [mmapped_file[i * chunk_size:(i + 1) * chunk_size].decode('utf-8', 'ignore') 
                  for i in range(num_chunks)]

        # Parallel processing
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
        pool.starmap(process_log_chunk, [(chunk, ip_failed_login_count, endpoint_counter, ip_request_counter) for chunk in chunks])

        pool.close()
        pool.join()

        return ip_failed_login_count, endpoint_counter, ip_request_counter

def display_results(ip_failed_login_count, endpoint_counter, ip_request_counter):
    """Display the results in a column-wise format."""
    print("Suspicious Activity Detected (Failed Login Attempts):")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in ip_failed_login_count.items():
        print(f"{ip:<20} {count}")

    print("\nMost Accessed Endpoint:")
    if endpoint_counter:
        endpoint, count = max(endpoint_counter.items(), key=lambda x: x[1])
        print(f"/{endpoint} (Accessed {count} times)")

    print("\nRequests per IP:")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in ip_request_counter.items():
        print(f"{ip:<20} {count}")

def save_to_csv(ip_failed_login_count, endpoint_counter, ip_request_counter):
    """Save the results to a CSV file."""
    import csv

    # Save IP failed login attempts to CSV
    with open('log_analysis_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in ip_failed_login_count.items():
            writer.writerow([ip, count])

    # Save most accessed endpoint
    with open('log_analysis_results.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Endpoint', 'Access Count'])
        if endpoint_counter:
            endpoint, count = max(endpoint_counter.items(), key=lambda x: x[1])
            writer.writerow([endpoint, count])

    # Save requests per IP
    with open('log_analysis_results.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_request_counter.items():
            writer.writerow([ip, count])

if __name__ == "__main__":
    # Path to the large log file
    file_path = 'sample.log'

    # Process the log file and get the results
    ip_failed_login_count, endpoint_counter, ip_request_counter = process_log_file(file_path)

    # Display results
    display_results(ip_failed_login_count, endpoint_counter, ip_request_counter)

    # Save results to CSV
    save_to_csv(ip_failed_login_count, endpoint_counter, ip_request_counter)
