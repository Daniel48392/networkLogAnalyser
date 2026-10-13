# networkLogAnalyser
 
A Java command-line tool that reads network security logs in **CEF (Common Event Format)**, groups the entries by source, and flags likely attacks. It currently detects:
 
- Brute force attempts
- Password spraying
- Vertical port scans
- Horizontal port scans
- Denial of service (DoS) activity
- SQL injection attempts
  
Each detected threat is printed to the terminal with its source IP, timestamps, attempt counts and a threat level.
 
## Requirements
- Developed in Java 17
- No external libraries or build tools are needed
  
## Project Structure
 
```
networkLogAnalyser/
├── logs/                               # CEF log files to analyse
│   |── exampleInputLog1.cef
|   ├── exampleInputLog2.log
|   └── exampleInputLog3.txt
├── src/
│   ├── Main.java                       # Entry point, prints results
│   ├── logData/
│   │   ├── log.java                    # One parsed CEF log line
│   │   ├── logReader.java              # Reads a CEF file into log objects
│   │   ├── logExtensionParser.java     # Helper for parsing CEF extension values
│   │   └── logCollection.java          # Runs detection and stores threat lists
│   └── logActivityAnalysis/
│       ├── activityAnalyser.java       # Detection logic for each attack type
│       └── activityTrackers/
│           ├── tracker.java                            # Base class for all trackers
│           ├── bruteForceTracker.java
│           ├── passwordSprayTracker.java
│           ├── portScanVerticalTracker.java
│           ├── portScanHorizontalTracker.java
│           ├── denialOfServiceTracker.java
│           ├── injectionSQLTracker.java
│           └── distributedDenialofServiceMonitor.java  # Placeholder (not yet implemented)
└── README.md
```
 
## Getting Started
 
### Clone
 
```bash
git clone https://github.com/Daniel48392/networkLogAnalyser.git
cd networkLogAnalyser
```
 
### Run
 
Run in Main.java and put the log files to be analysed in /logs directory, then in the first line of the public static main method, change the string in logCollection.organiseLogs(...) to your desired filename.
Then run Main.java.
 
## Log Format
 
Logs must be in CEF, one event per line:
 
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```
 
The analyser reads these extension fields:
 
| Field   | Meaning             |
| ------- | ------------------- |
| `src`   | Source IP           |
| `dst`   | Destination IP      |
| `spt`   | Source port         |
| `dpt`   | Destination port    |
| `suser` | Source user         |
| `duser` | Destination user    |
| `rt`    | Receipt time        |
| `act`   | Action              |
| `msg`   | Message             |
| `proto` | Protocol            |
 
Notes on parsing:
- `rt` can be epoch milliseconds or a date in the form `MMM dd yyyy HH:mm:ss` (interpreted as UTC).
- Severity can be a number or one of: `very low`, `informational`, `low`, `medium`, `high`, `very high`, `critical`.
- Fields that are missing from a line are treated as `null` and that line is skipped by any detector that needs them.
## How Detection Works
 
All logs are read and parsed first. Each attack detector then groups. Logs flagged as SQL injection are excluded from every other detector.
 
| Attack | Grouped by | What is counted | Reported when |
| ------ | ---------- | --------------- | ------------- |
| Brute force | Source IP + destination IP | Login attempts (classified as failed, successful or unknown) | More than 8 attempts |
| Password spray | Source IP | Distinct accounts targeted | More than 8 accounts |
| Vertical port scan | Source IP + destination IP | Distinct destination ports | More than 10 ports |
| Horizontal port scan | Source IP + destination port | Distinct destination IPs | More than 10 IPs |
| Denial of service | Source IP | All events with a destination port | More than 15 events |
| SQL injection | Source IP + destination IP | Events matching injection syntax | Any match |
 
Additional behaviour:
 
- **DoS filtering:** a source IP already reported for brute force, password spray or a port scan is not also reported as DoS.
- **SQL injection patterns:** a log is flagged if it contains the text "sql injection" or matches common payloads such as `OR 1=1`, `UNION SELECT`.
- **Threat level:** calculated as the threat's event count divided by the total number of logs read. Above 0.2 is **High**, above 0.1 is **Medium**, otherwise **Low** - however this is **to be reworked** and is **NOT** a reliable indicator for genuine threat level.
## Example Output
 
```
Brute Force:
/////////////////////////
Source IP: 203.0.113.45
Target User: admin
First Seen: 2026-01-12T09:14:02Z
Last Seen: 2026-01-12T09:16:47Z
Attempts: 24
Failed: 23
Successful: 1
Unknown: 0
Threat Level: 0.12 |Medium|
/////////////////////////
```
 
Results are printed in sections: Brute Force, Password Spray, Vertical Port Scan, Horizontal Port Scan, Denial Of Service and SQL Injection. (The values above are illustrative.)
 
## Known Limitations and Roadmap
- The input filename is hard-coded in `Main.java`.
- Distributed denial of service (DDoS) detection is a placeholder (`distributedDenialofServiceMonitor`), future improvement to add DDOS detection instead of outputing many individual DOS attacks.
- The threat scoring system is basic and marked for rework.
- The CEF extension parser can misread values that contain a space followed by an `=` sign.
- Originally designed to read 5000 logs at a time to reduce memory required but made the program very inefficient, future improvement would be to make the program more efficient and read log files in chunks.
