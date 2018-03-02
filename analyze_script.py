import re
import sys

# Declaration to store the different results into respective array
SQLi = []
file_inclusion = []
web_shell = []

# Open the file specified by the user and read it
file = open(sys.argv[1], 'r')

# Create 3 files with writing permission to display the results
sqli_file = open('sqli.txt' , 'w')
fc_file = open('fileinclusion.txt' , 'w')
ws_file = open('webshell.txt' , 'w')

# For each individual line in the file, do 3 checks
for eachline in file:

    # SQLi checks
    if re.search(r'((\%27)|(\'))select', eachline) \
       or re.search(r'((\%27)|(\'))union', eachline) \
       or re.search(r'((\%27)|(\'))insert', eachline) \
       or re.search(r'((\%27)|(\'))update', eachline) \
       or re.search(r'((\%27)|(\'))delete', eachline) \
       or re.search(r'((\%27)|(\'))drop', eachline) \
       or re.search(r'\b\FROM', eachline) \
       or re.search(r'\b1=1\b', eachline):
            SQLi.append(eachline)

    # File Inclusion Checks    
    if (re.search(r'\bfile=', eachline) and re.search(r'/*', eachline)) \
       or (re.search(r'\bpage=', eachline) and re.search(r'/*', eachline)) \
       or re.search(r'((\%3D\%2E\%2E/)|\=\.\./)', eachline) \
       or re.search(r'(\%25\%30\%30|\%00)', eachline):
            file_inclusion.append(eachline)

    # Webshell Checks
    if re.search(r'\baction=upload', eachline) \
       or re.search(r'\bcmd=', eachline) \
       or re.search(r'\bb374k', eachline) \
       or re.search(r'\bc100', eachline) \
       or re.search(r'\bc99', eachline) \
       or re.search(r'\bwso', eachline) \
       or re.search(r'\br57', eachline) \
       or re.search(r'\brangel', eachline) \
       or re.search(r'\bbv7binary', eachline) \
       or re.search(r'\bwebroot', eachline) \
       or re.search(r'\bkacak', eachline) \
       or re.search(r'\bsymlink', eachline) \
       or re.search(r'\bh4cker', eachline) \
       or re.search(r'\bwebadmin', eachline) \
       or re.search(r'\bgazashell', eachline) \
       or re.search(r'\blocus7shell', eachline) \
       or re.search(r'\bsyianshell', eachline) \
       or re.search(r'\binjection', eachline) \
       or re.search(r'\bcyberwarrior', eachline) \
       or re.search(r'\bernebypass', eachline) \
       or re.search(r'\bg6shell', eachline) \
       or re.search(r'\bpouyaserver', eachline) \
       or re.search(r'\bsaudishell', eachline) \
       or re.search(r'\bsimattacker', eachline) \
       or re.search(r'\bsosyeteshell', eachline) \
       or re.search(r'\btryagshell', eachline) \
       or re.search(r'\buploadshell', eachline) \
       or re.search(r'\bzehir4shell', eachline) \
       or re.search(r'\blostdcshell', eachline) \
       or re.search(r'\bcommandshell', eachline) \
       or re.search(r'\bmailershell', eachline) \
       or re.search(r'\bcwshell', eachline) \
       or re.search(r'\biranshell', eachline) \
       or re.search(r'\bindishell', eachline) \
       or re.search(r'\bsqlshell', eachline) \
       or re.search(r'\bunknown', eachline) \
       or re.search(r'\bk2ll33d', eachline) \
       or re.search(r'\bb1n4ry', eachline) \
       or re.search(r'\bweevely', eachline):
            web_shell.append(eachline)

print ("Analyzing of \"" + sys.argv[1] +"\" is Completed.")


# Printing of results from the SQLi array into "sqli.txt"
sqli_file.write("SQL Injection Detected: \n")

for line in SQLi:
    sqli_file.write(line)
print ("SQL Injection Printing Completed in \"sqli.txt\". ")

# Printing of results from the file_inclusion array into "fileinclusion.txt"
fc_file.write("File Inclusion Detected: \n")

for line in file_inclusion:
    fc_file.write(line) 
print ("File Inclusion Printing Completed in \"fileinclusion.txt\". ")

# Printing of results from the web_shell array into "webshell.txt"
ws_file.write("Web Shell Detected: \n")

for line in web_shell:
    ws_file.write(line) 
print ("Web Shell Printing Completed in \"webshell.txt\". ")

# Close the 3 files
sqli_file.close()
fc_file.close()
ws_file.close()
