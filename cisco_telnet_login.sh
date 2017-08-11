#!/usr/bin/python


import optparse
import os
import sys
import logging
import telnetlib
import datetime
import time
import re
parser=optparse.OptionParser()
(options, args) = parser.parse_args()
# =============== Setup Logging ===============

logger = logging.getLogger()
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

stream_handler.setFormatter(formatter)

logger.addHandler(stream_handler)

#============= create output file==============

#def timeStamped(fname, fmt='%Y-%m-%d-%H-%M-%S_{fname}'):
#    return datetime.datetime.now().strftime(fmt).format(fname=fname)
#
#file = open(timeStamped('traffic.txt'),'w+')
#

#============= connection details =============
PORT = "23"

# ======================== username function ======================


#============ Check number of arguments ====================
if len(sys.argv) != 5:
        print("usage: {0} {1} {2} {4} Enter username password, enable passowrd and ip address in that order").format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(2)


#============ Get credentials from command line parameters  ====================
password = sys.argv[2]
en_password = sys.argv[3]
username = sys.argv[1]
HOST = sys.argv[4]
password.strip()
username.strip()
# ==================== Get script execution time ===================
execution_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print 'mSAS Execution time is: {time}'.format(time=execution_time)


# ==================== Get mSAS IP address(es) ===================
status = os.system("echo \"mSAS IP:\" `/sbin/ifconfig | grep -oE 'inet addr:([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]).([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]).([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]).([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])' | grep -v '127.0.0.1' | cut -d \":\" -f 1 --complement | tr '\n' '|' | sed -e 's/|$/''/g'`")



# ==================== Get mSAS hostname  ===================
print 'Hostname is: {hostname}'.format(hostname=os.uname()[1])


#============= Open connection =================
tn = telnetlib.Telnet(HOST, PORT)


#============= Enter Commands =================

tn.write("\n")
result = tn.expect([r"\bUser Access Verification\b"])
print result

case = result[0]

if case == 0:
        print('Connection established in the expected state, continuing with login...')

elif case == 1:
        print('System not responding to normal telnet login prompt, logging out before proceeding with script execution...')
        tn.write("\n")


else:
     print("System found in an unknown state")
     sys.exit(1)

# ================================ Login process =====================================#
DEFAULT_TELNET_EXPECT_TIMEOUT = 10
DEFAULT_CISCO_RETRY_COUNT = 10
cisco_attempts = 1 # We make at least 1 attempt

while cisco_attempts < DEFAULT_CISCO_RETRY_COUNT:
    result1 = tn.expect([r"\bUsername\b", "Password:", "#", ">"], DEFAULT_TELNET_EXPECT_TIMEOUT)
    logger.debug("tn.expect result: " + str(result))
    print result1[2]

    case = result1[0]

    if case == 0:
        logger.info("Username configured")
        logger.debug("logging in")
        print ("Usermode0"), tn.read_some()
        tn.write("{0}".format(username))
        time.sleep(2)
        print ("Usermode1"), tn.read_some()
        tn.write("\n")
        print ("Usermode2"), tn.read_some()
        tn.expect(["Password:"], DEFAULT_TELNET_EXPECT_TIMEOUT)
        tn.write("{0}".format(password))
        time.sleep(2)
        tn.write("\n")
        time.sleep(2)
        print ("Usermode3"), tn.read_some()
        time.sleep(2)
        tn.write("\n")
        tn.expect(["#"], DEFAULT_TELNET_EXPECT_TIMEOUT)

    elif case == 1:
        logger.info("Password only mode")
        logger.debug("entering password mode")
        tn.write("\n")
        tn.expect(["Password:"])
        tn.write("{0}\n".format(password))
        time.sleep(2)
        tn.write("\n")
        time.sleep(2)
        print ("Password mode1"), tn.read_some()
        time.sleep(2)
        tn.write("\n")
        tn.expect([">"])
        tn.write("en\n")
        tn.write("{0}\n".format(en_password))
        time.sleep(2)
        tn.write("\n")
        tn.expect(["#"])

    elif case == 2:
        logger.info("Login Successful.")
        tn.write("terminal len 0" + "\n")
        tn.expect(["#"])
        tn.write("\n")
        print ("Privileged mode already on"), tn.read_until("#")
        tn.write("\n")
        tn.expect(["#"])
        break # login successful proceed to commands

    elif case == 3:
        tn.write("\n")
        print ("G1"), tn.read_until(">")
        tn.write("\n")
        tn.expect([">"])
        tn.write("en" + "\n")
        tn.write("{0}\n".format(en_password))
        time.sleep(2)
        tn.write("\n")
        print ("Privileged mode test1"), tn.read_until("#")

        tn.write("\n")
        print ("Privileged mode test2"), tn.read_until("#")
        tn.write("\n")
        time.sleep(2)
        tn.write("\n")
        tn.expect(["#"])


    else:
        logger.warning("Username Login attempt " + str(cisco_attempts) + " unsuccessful, retrying.")
        logger.debug("Issuing 'exit\n'") # Sednign **** to retry exiting a load and cause more output to appear in an attempt to log out
        tn.write("\n")
        cisco_attempts += 1

    if cisco_attempts >= DEFAULT_CISCO_RETRY_COUNT:
        logger.error("Login Unsuccessful after " +str(cisco_attempts) + ", closing Telnet connection.")
# ========================================= commands section =========================================
tn.write("\n")
host_name = tn.read_until("#")
host_name = re.sub('[!#@$?]', '', host_name)

def timeStamped(fname, fmt='%Y-%m-%d-%H-%M-%S_{fname}'):
    return datetime.datetime.now().strftime(fmt).format(fname=fname)

file = open(timeStamped("{0}.txt".format(host_name)),'w+')


file.write ("\n======================== ip traffic ===========================\n")
tn.write("show ip traffic" + "\n")
file.write(tn.read_until("#"))
tn.write("\n")
tn.expect(["#"])
file.write ("\n======================== cpu ===========================\n")
tn.write("show processes cpu\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect([r"#"])
file.write ("\n======================== auto qos ===========================\n")
tn.write("show auto qos\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect([r"#"])
file.write ("\n======================== spanning tree ===========================\n")
tn.write("show spanning-tree\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect([r"#"])
file.write ("\n======================== show log ===========================\n")
tn.write("show log\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect([r"#"])
file.write ("\n======================== show interfaces summary ===========================\n")
tn.write("show interfaces summary\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect([r"#"])
file.write ("\n======================== show interfaces status ===========================\n")
tn.write("show interfaces status\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect([r"#"])
file.write ("\n ======================== show interfaces trunk ===========================\n")
tn.write("show interfaces trunk\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect(["#"])
file.write ( "\n========================== show cdp neighbors ===============================\n")
tn.write("show cdp neighbors" + "\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect(["#"])

file.write ("\n========================== show sip-ua statistics(VG224) ===============================\n")

tn.write("sh sip-ua statistics" + "\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect(["#"])


file.write ("\n========================== show sip-ua status(VG224) ===============================\n")

tn.write("sh sip-ua status" + "\n")
file.write (tn.read_until("#"))
tn.write("\n")
tn.expect(["#"])



# ========================= logout ===================================

print ("logout")
tn.write("exit\n")
