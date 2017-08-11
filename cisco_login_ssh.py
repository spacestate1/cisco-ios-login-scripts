#!/usr/bin/python


import optparse
import os
import sys
import logging
import telnetlib
import datetime
import time
import re
import pexpect
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

ssh_newkey = 'Are you sure you want to continue connecting'
#============= Open connection =================
p=pexpect.spawn('ssh {0}@{1}'.format(username, HOST))



#============= Enter Commands =================
#DEFAULT_SSH_EXPECT_TIMEOUT = 10
#DEFAULT_CISCO_RETRY_COUNT = 10
#cisco_attempts = 1 # We make at least 1 attempt
#while cisco_attempts < DEFAULT_CISCO_RETRY_COUNT:
#    result1 = p.expect([ssh_newkey,"Login as", "password:", "#"], DEFAULT_SSH_EXPECT_TIMEOUT)
#    print (result1)
#    if result1 == 0:
#        print "first time connection: saying YES"
#        p.sendline('yes')
#        p.expect([':'])
#    elif result1 == 1:
#        print "Entering username",
#        p.sendline(username + "\n")
#        p.expect(['password'])
#        p.sendline(password + "\n")
#        p.expect(['#'])
#    elif result1 == 2:
#        print ("Password")
#        p.sendline(password + "\n")
#        p.expect(['#'])
#        print p.before
#    elif result1 == 3:
#        print ("Connection Established")
#        p.sendline("\n")
#        p.expect(['#'])
#        print p.before
#
#        break
#    else:
#        cisco_attempts = (cisco_attempts + 1)
#print ("entering ls")
#p.sendline("\n")
#p.expect(['#'])
#print(pexpect.run('ls'))
#p.expect([r'.*#'])
#print(pexpect.run('ifconfig'))
#p.expect([r'.*#'])
#case = result1[0]
#
#if case == 0:
#    print('Connection established in the expected state, continuing with login...')
#
#elif case == 1:
#    print('System not responding to normal telnet login prompt, logging out before proceeding with script execution...')
#    p.sendline("\n")
#
#
#else:
#     print("System found in an unknown state")
#     sys.exit(1)
#
## ================================ Login process =====================================#
print ("ssh {0}@{1}".format(username, HOST))
print (password)

DEFAULT_SSH_EXPECT_TIMEOUT = 10
DEFAULT_CISCO_RETRY_COUNT = 10
cisco_attempts = 1 # We make at least 1 attempt

while cisco_attempts < DEFAULT_CISCO_RETRY_COUNT:
    result1 = p.expect([r"\bUsername\b", "Password:", "#", ">"], DEFAULT_SSH_EXPECT_TIMEOUT)
    logger.debug("p.expect result: " + str(result1))
    print result1

    case = result1

    if case == 0:
        logger.info("Username configured")
        logger.debug("logging in")
        print ("Usermode0")
        p.sendline("{0}".format(username))
        time.sleep(2)
        print ("Usermode1")
        p.sendline("\n")
        print ("Usermode2")
        p.expect(["Password:"], DEFAULT_SSH_EXPECT_TIMEOUT)
        p.sendline("{0}".format(password))
        time.sleep(2)
        p.sendline("\n")
        time.sleep(2)
        print ("Usermode3")
        time.sleep(2)
        p.sendline("\n")
        p.expect(["#"], DEFAULT_SSH_EXPECT_TIMEOUT)

    elif case == 1:
        logger.info("Password only mode")
        logger.debug("entering password mode")
        p.sendline("\n")
        p.expect(["Password:"])
        print (p.before)
        p.sendline("{0}\n".format(password))
        time.sleep(2)
        p.sendline("\n")
        print (p.before)
        time.sleep(2)
        print ("Password mode 1")
        time.sleep(2)
        p.sendline("\n")
        p.expect(["#"])
        print (p.before)
        print ("Password mode 2 (password accepted)")

    elif case == 2:
        logger.info("Login Successful.")
        p.sendline("terminal len 0" + "\n")
        p.expect(["#"])
        p.sendline("\n")
        print ("Now in Privileged EXEC mode")
        p.sendline("\n")
        p.expect(["#"])
        print (pexpect.run('show cdp neighbors'))
        break # login successful proceed to commands

    elif case == 3:
        p.sendline("\n")
        print ("G1")
        p.sendline("\n")
        p.expect([">"])
        p.sendline("en" + "\n")
        p.sendline("{0}\n".format(en_password))
        time.sleep(2)
        p.sendline("\n")
        print ("Privileged mode test1")

        p.sendline("\n")
        print ("Privileged mode test2")
        p.sendline("\n")
        time.sleep(2)
        p.sendline("\n")
        p.expect(["#"])


    else:
        logger.warning("Username Login attempt " + str(cisco_attempts) + " unsuccessful, retrying.")
        logger.debug("Issuing 'exit\n'") # Sednign **** to retry exiting a load and cause more output to appear in an attempt to log out
        p.sendline("\n")
        cisco_attempts += 1

    if cisco_attempts >= DEFAULT_CISCO_RETRY_COUNT:
        logger.error("Login Unsuccessful after " +str(cisco_attempts) + ", closing Telnet connection.")
# ========================================= commands section =========================================
p.sendline("\n")
host_name = p.before
host_name = re.sub('[!#@$?]', '', host_name)

def timeStamped(fname, fmt='%Y-%m-%d-%H-%M-%S_{fname}'):
    return datetime.datetime.now().strftime(fmt).format(fname=fname)

file = open(timeStamped("{0}.txt".format(host_name)),'w+')


file.write ("\n======================== ip traffic ===========================\n")
file.write(pexpect.run('show ip traffic'))
p.sendline("\n")
p.expect(["#"])
#file.write ("\n======================== cpu ===========================\n")
#p.sendline("show processes cpu\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect([r"#"])
#file.write ("\n======================== auto qos ===========================\n")
#p.sendline("show auto qos\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect([r"#"])
#file.write ("\n======================== spanning tree ===========================\n")
#p.sendline("show spanning-tree\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect([r"#"])
#file.write ("\n======================== show log ===========================\n")
#p.sendline("show log\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect([r"#"])
#file.write ("\n======================== show interfaces summary ===========================\n")
#p.sendline("show interfaces summary\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect([r"#"])
#file.write ("\n======================== show interfaces status ===========================\n")
#p.sendline("show interfaces status\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect([r"#"])
#file.write ("\n ======================== show interfaces trunk ===========================\n")
#p.sendline("show interfaces trunk\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect(["#"])
#file.write ( "\n========================== show cdp neighbors ===============================\n")
#p.sendline("show cdp neighbors" + "\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect(["#"])
#
#file.write ("\n========================== show sip-ua statistics(VG224) ===============================\n")
#
#p.sendline("sh sip-ua statistics" + "\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect(["#"])
#
#
#file.write ("\n========================== show sip-ua status(VG224) ===============================\n")
#
#p.sendline("sh sip-ua status" + "\n")
#file.write (tn.read_until("#"))
#p.sendline("\n")
#p.expect(["#"])
#
#
#
## ========================= logout ===================================
#
#print ("logout")
#p.sendline("exit\n")
