# Apache Log Analyzer
1. This python script (analyze_script.py) helps to analyze the log file and detects 4 attacks:   
   1. SQL Injections
   2. File Inclusions
   3. Webshell
   4. Illegal Access (HTTP Status Code 401, 403)

   After successful detection, this python script will generate 4 files:
   1. sqli.txt (for SQL Injections)
   2. fileinclusion.txt (for File Inclusion)
   3. webshell.txt (for Webshell)
   4. illegalaccess.txt (for Illegal Access)
   
# User Guide (analyze_script.py)
1. Open a command prompt (by holding shift + right click in the specific folder that both analyze_script.py and the log file is) 
   and the command prompt will be launched.

2. In the command prompt, type in the parameters in the following format (analyze_script.py <log file's name>)
   - analyze_script.py CTF1.log

3. After entering the commands, wait for the following messages to be printed out to notify that the checks are completed:
   - Analyzing of "<xxx.log>" is Completed.
   - SQL Injection Printing Completed in "sqli.txt".
   - File Inclusion Printing Completed in "fileinclusion.txt".
   - Web Shell Printing Completed in "webshell.txt".
   - Illegal Access Printing Completed in "illegalaccess.txt".

# Installation Guide
1. This python script (analyze_script.py) was built on Python Version 3.4.3.
   Download link for Python Version 3.4.3: https://www.python.org/downloads/
