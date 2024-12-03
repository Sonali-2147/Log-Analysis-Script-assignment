# Log Analysis Script  

## *Overview*  
This Python script processes log files to extract and analyze key information related to requests per IP address, frequently accessed endpoints, and suspicious activity detection. It is designed for cybersecurity-related programming tasks, emphasizing file handling, string manipulation, and data analysis.  

---

## *Features*  
1. *Requests per IP Address*  
   - Counts and displays the number of requests made by each IP address.  
   - Results are sorted in descending order of request counts.  

2. *Most Accessed Endpoint*  
   - Identifies the most frequently accessed endpoint (e.g., URLs or resource paths).  
   - Displays the endpoint name and its access count.  

3. *Suspicious Activity Detection*  
   - Flags IPs with failed login attempts (e.g., HTTP 401 status or "Invalid credentials").  
   - Configurable threshold for detecting suspicious activity (default: 10 failed attempts).  

4. *Output Results*  
   - *Terminal:* Results are displayed in a clear and organized format.  
   - *CSV File:* Saves results in log_analysis_results.csv with the following structure:  
     - Requests per IP: IP Address, Request Count  
     - Most Accessed Endpoint: Endpoint, Access Count  
     - Suspicious Activity: IP Address, Failed Login Count  

---

## *Requirements*  
- Python 3.6 or above.  

### *Dependencies*  
The script uses Python's standard library. No external packages are required.  

---

## *Usage Instructions*  

### *Step 1: Prepare the Log File*  
Ensure the log file (e.g., sample.log) is in the same directory as the script or specify its path when running the script.  

### *Step 2: Run the Script*  
1. Open a terminal or command prompt.  
2. Navigate to the script directory.  
3. Execute the script:  
   bash
   python log_analysis.py
     

### *Step 3: View the Output*  
- *Terminal:* View results for each analysis section.  
- *CSV File:* Check the generated log_analysis_results.csv for a structured summary.  

### *Optional: Adjust Threshold for Suspicious Activity*  
Edit the script to modify the THRESHOLD variable:  
python
THRESHOLD = 10 # Change this value to set a custom threshold.
  

---

## *Files Included*  
1. *log_analysis.py*: Main script for log analysis.  
2. *sample.log*: Example log file for testing.  
3. *log_analysis_results.csv*: Generated output file with analysis results.  

---

![Screenshot 2024-12-03 130611](https://github.com/user-attachments/assets/2834596b-0d42-46da-9e9c-8684654c49f7)


## *Contact*  
For questions or support, please reach out at kadamsonali2147@gmail.com.
