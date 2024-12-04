Log Analysis Script

This script processes a log file to analyze request counts per IP address, track the most accessed endpoints, and detect suspicious activity (failed login attempts). It is designed to efficiently handle large log files, such as those reaching 100GB, by using memory-mapped files and multiprocessing.
Features

    IP Request Count: Tracks the number of requests made by each IP address.
    Most Accessed Endpoint: Identifies the most frequently accessed endpoint from the log file.
    Suspicious Activity Detection: Detects failed login attempts (401 status code) and tracks suspicious activity by IP address.
    Efficient Processing: Utilizes memory-mapped files and multiprocessing for handling large log files with high performance.

Requirements

    Python 3.x
    re (regular expressions library) – built-in in Python
    collections (defaultdict, Counter) – built-in in Python
    multiprocessing – built-in in Python
    mmap – built-in in Python

Installation

To use the script, clone the repository to your local machine:

git clone https://github.com/jashwanthvemula/Log-Analysis-Script.git
cd Log-Analysis-Script

No additional installations are required as the necessary libraries are part of Python's standard library.
Usage

    Make sure your log file is available (e.g., sample.log).
    Open the script and update the file_path variable with the path to your log file.
    Run the script:

python Log-Analysis-Script

The script will:

    Display the number of requests per IP address.
    Show the most accessed endpoint.
    List IP addresses with suspicious activity (failed login attempts).

Output

    Terminal Output: The script will display the results in a clear, organized format.
    CSV Output: The results will also be saved to a file named log_analysis_results.csv with the following structure:
        Requests per IP: IP Address, Request Count
        Most Accessed Endpoint: Endpoint, Access Count
        Suspicious Activity: IP Address, Failed Login Count

Example Output
Terminal Output:

Suspicious Activity Detected:
IP Address         Failed Login Attempts
-----------------------------------------------------
192.168.1.1        5
192.168.1.2        3

Most Frequently Accessed Endpoint:
/login (Accessed 150 times)

Requests per IP:
IP Address         Request Count
-----------------------------------------------------
192.168.1.1        500
192.168.1.2        300

CSV Output (log_analysis_results.csv):

IP Address,Request Count
192.168.1.1,500
192.168.1.2,300

Endpoint,Access Count
/login,150

IP Address,Failed Login Count
192.168.1.1,5
192.168.1.2,3

Performance

    The script is designed to handle large log files efficiently, utilizing memory-mapped files and multiprocessing.
    For very large files (100GB+), the script splits the log into chunks and processes them in parallel using available CPU cores, which ensures fast execution without overloading the memory.
