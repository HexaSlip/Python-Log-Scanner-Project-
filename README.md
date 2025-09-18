# Python Log Scanner
A simple yet effective Python tool for scanning log files, identifying common security threats, and providing geolocation data for suspicious IP addresses.

## Features ##
- Threat Detection: Identifies a range of security events, including failed logins, SQL injections, directory traversal, and more.

- IP Geolocation: Uses the MaxMind GeoLite2 database to provide city and country information for IP addresses found in the logs.

- Customizable: Easily extendable to include new log formats and threat patterns.

- Detailed Summary: Provides a clear and concise summary of all alerts found across all scanned files.

## Getting Started ##

### Prerequisites ###
1. Get the Code: You can clone the repository to your machine by running this command in your terminal:
  ``` git clone [https://github.com/HexaSlip/Python-Log-Scanner-Project-/blob/main/log_scanner.py]. ```
Alternatively, you can view the main script file [here](https://github.com/HexaSlip/Python-Log-Scanner-Project-/blob/main/log_scanner.py)

2. Python 3.6+: Ensure you have Python installed. You can check with
  ` python3 --version.`
 3. Create a Virtual Environment: It is highly recommended to use a virtual environment to manage this project's dependencies. 
 4. Activate the Virtual Environment:
- on macOS and Linux:
     ` source venv/bin/activate`
- on Windows:
      `venv/Scripts/activate`
5. Required Libraries: Install the necessary Python packages using pip.

` pip install geoip2 `

6. #### MaxMind GeoLite2 Database: This tool requires the free GeoLite2-City database for geolocation.

- Sign up for a free MaxMind account [here](https://www.maxmind.com/)

- Generate a license key (you will need it for future updates, but not for initial setup).

- ##### Download the GeoLite2-City database in the ``` .mmdb.gz ``` format.

- Unzip the file and place the resulting ` GeoLite2-City.mmdb ` file in the same directory as this script.

### Usage ###
Run the script from your terminal and provide the path to the log file(s) you want to scan.

``` python3 log_scanner.py [path_to_file_1.log] [path_to_file_2.log] ... ```

### Example:

` python3 log_scanner.py example.log `

### Example Output
Here is an example of what the tool's output looks like:
```
Scanning example.log...

[ALERT - Failed login]from None, United States | 2025-09-17 11:30:15 ERROR Failed password for admin from 66.249.66.1
[ALERT - Error]from None, United States | 2025-09-17 11:31:02 ERROR Attempted SQL Injection from 185.199.108.153
[ALERT - IP Address]from Fremont, United States | 2025-09-17 11:34:10 WARNING Directory traversal attempt ../../etc/shadow from 45.33.32.255

--- Summary ---
Failed login: 2 alert(s)
Error: 4 alert(s)
Directory Traversal: 1 alert(s)
... and so on
```
### How it Works ###
This tool processes log files line by line, using regular expressions to identify specific security keywords, phrases, and IP addresses. Once a match is found, it performs a lookup against the GeoLite2 database to provide geolocation data, enriching the security alert with actionable intelligence about the origin of the threat. 

#### Important Notice ####
_This tool is intended for educational and ethical purposes only. Unauthorized scanning of networks, or the use of illegal IP addresses to test against the tool, is strictly prohibited. Use only legally obtained log files or IP addresses for which you have explicit permission to scan. You are solely responsible for your actions._

## Contributing ##
Your contributions are what make open-source projects great! If you have an idea, find a bug, or just want to discuss a new feature, feel free to open a new issue. 
You can also create a pull request with your suggested changes. If you have an idea you'd like to work on, you can open an issue and mention me(@HexaSlip) to let me know what you're thinking.  

## License
This project is licensed under the MIT License.
