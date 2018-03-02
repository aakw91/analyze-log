# User Manual (analyze_script.py)
Brief Info
1. This python script (analyze_script.py) was built on Python Version 3.4.3.
   Download link for Python Version 3.4.3: https://www.python.org/downloads/

2. This python script (analyze_script.py) helps to analyze the log file and detects 3 attacks:   
   1. SQL Injections
   2. File Inclusions
   3. Webshell

   After successful detection, this python script will generate 3 files:
   1. sqli.txt (for SQL Injections)
   2. fileinclusion.txt (for File Inclusion)
   3. webshell.txt (for Webshell)

Steps to Execute
3. Open a command prompt (by holding shift + right click in the specific folder that both analyze_script.py and the log file is) 
   and the command prompt will be launched.

4. In the command prompt, type in the parameters in the following format (analyze_script.py <log file's name>)
   - analyze_script.py CTF1.log

5. After entering the commands, wait for the following messages to be printed out to notify that the checks are completed:
   - Analyzing of "<file name.log>" is Completed.
   - SQL Injection Printing Completed in "sqli.txt".
   - File Inclusion Printing Completed in "fileinclusion.txt".
   - Web Shell Printing Completed in "webshell.txt".
