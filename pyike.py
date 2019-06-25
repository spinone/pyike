#!/usr/bin/env python
# -*- coding: utf-8 -*-

#python 2.7 Linux

"""pyike.py: A script to check VPN endpoint support for Aggressive Mode with various Authorisation parameters. """
# Allows a choice of intensities (varying numbers of transforms, hashes and DH groups). Use -h for help.
# Checks single or multiple targets for UDP port 500 open and ike-scans them in aggressive mode if they are, 
# (it prints the command to validate this) and prints the responder hash (with caveat). 
# Checks the implementation fingerprint (guesses the vendor).
# Checks to see if port 4500 is open and suggests nat-t if it is.
# Checks to see if Dead Peer Detection is reported (missing for an incorrect group name from an unpatched ASA firewall)

# To Do:   #
# NAT mode, port variable (500/4500) for output #

__author__ = 'Chris Rundle (crundle@blackberry.com)'
__version__ = '1.2.9'
__last_modification__ = '2019.06.12'
# 1.2.6 = Parse CIDR ranges in a file list
# 1.2.7 = Default to non-verbose mode (only report aggressive), with -v to show verbose output
# 1.2.8 = Cosmetic changes to output
# 1.2.9 = Added hash_r warning, Dead Peer Detection and insane mode (all 23760 transforms)

# Import modules #

import sys
import os
import subprocess
import socket
import time

# Functions #

def usage():
        print "Usage: (Run as root or using sudo)\n\n       pyike.py [-h][-v][-q][-n][-L: ][-Tx] target \n         -h =  This information (also --help)\n         -v =  Report verbosely (all targets), not just when Aggressive mode is found\n         -q =  Quick - Report when Aggressive mode is found, but don't perform an implementation check\n               (i.e. don't guess the VPN vendor)\n         -n =  Disable port check - IKE scan all targets even if port 500/udp is not open (slow)\n         -L:<filename> - read targets from a list of valid IP addresses and/or CIDR ranges\n         -Tx = Intensity: -T1 light (45 transforms & PSK only), -T2 default (180), -T3 high (750), -T4 insane (23760)\n\n         target = A space delimited combination of IPs, x-y IP ranges, CIDR ranges or hostnames\n             e.g. pyike.py 5.25.16.0/30 212.16.82.5-10 encription.co.uk\n             or   pyike.py -q -T1 212.16.82.5-10 -L:hostlist1.txt -L:hostlist2.txt\n\n"

def chkroot():
    if len(sys.argv)==1:
        print "\n[!] No targets to test...\n"
        usage()
        sys.exit()

    if not os.geteuid() == 0:
        # Must be root to bind network socket to port 500
        xt="[***] ERROR: You must be root to run this script! (or use sudo)"

        try:
            print('\n\x1b[0;31;47m' + xt + '\x1b[0m' + '\n') # ANSI Escape sequence for red text on white backround.
        except: # ANSI ESC may not work on all Windows consoles.
            print xt

        # print '\033[1;38m[***] ERROR: You must be root to run this script! (or use sudo)\033[1;m' # Just BOLD

        sys.exit(-1)

    isx = subprocess.call("type " + "ike-scan", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0
    if not isx:
        sys.exit("\n[***] Can't find ike-scan - is it in your PATH?\n")

    isx = subprocess.call("type " + "nmap", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0
    if not isx:
        sys.exit("\n[***] Can't find nmap - is it in your PATH?\n")

def chkVal(x): # checks if a value is a number between 0 and 255
    try:
        float(x)
    except ValueError:
        return False
    if not 0 <= int(x) <= 255:
        return False
    return True

def validIP(address): # checks if the target is a valid IP address
    rval=True
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not chkVal(item):
            return False
    return True

def IPlist(addressrange): # checks if target is a valid IP range
    parts = addressrange.split(".")
    if len(parts) != 4:
        return False
    for i in range(0,3):
        if not chkVal(parts[i]):
            return False
    listparts=parts.pop().split("-")
    if len(listparts) != 2:
        return False
    for item in listparts:
        if not chkVal(item):
            return False
    return True
       

def iprange(addressrange): # converts an IP range into a list
    list=[]
    first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
    for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
        list.append(first3octets+str(i))
    return list

def ip2bin(ip): # Required for CIDR
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "": b += dec2bin(int(q),8); outQuads -= 1
    while outQuads > 0: b += "00000000"; outQuads -= 1
    return b

def dec2bin(n,d=None): # Required for CIDR
    s = ""
    while n>0:
        if n&1: s = "1"+s
        else: s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d: s = "0"+s
    if s == "": s = "0"
    return s

def bin2ip(b): # Required for CIDR
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def returnCIDR(c): # returns a list from a CIDR range
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    ips=[]
    if subnet == 32: #return list(bin2ip(baseIP))
        ips.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return ips

def chkport(IP): # Check if port 500/udp is open
    open500=False
    open4500=False
    cmd="nmap -Pn -sU -p500,4500 " + IP 
    cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in cmd.stdout: # Loop through Nmap output looking for open ports 500 & 4500
        if " open " in line: # not open|filtered
            if "4500" in line:
                open4500=True
                if nat=="":
                    print "[!]  Port 4500/udp is open - consider using NAT-Traversal (-nat)"
            else: # if it's open and it's not 4500, it must be 500
                open500=True
    return open500

def gentrans(LEN): # Make a list of all appropriate transforms
    # taken from http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide 
    translist=[]

    ENCLIST=['1','5','7/128','7/192','7/256']# Encryption: DES, Triple-DES, AES/128, AES/192 and AES/256
    HASHLIST=['1','2','4']# Hashes: MD5, SHA1 & SHA2-256 [+ possibly 5 (SHA2-384), 6 (SHA2-512)]
    AUTHLIST=['1','3','64221','65001']# Authentication: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH [+ 4 (RSA Encryption), 8 (ECDSA Signature)]
    GROUPLIST=['1','2','5']# Diffie-Hellman groups: 1, 2 and 5 (but potentially 1-18)

    if LEN == 1:
	    AUTHLIST=['1'] # If we only need PSK for this check, but use the default (T2) ENCLIST, HASHLIST and GROUPLIST

    if LEN == 3:
        HASHLIST=['1,','2','4','5','6']# Hashes: MD5, SHA1, SHA2-256, SHA2-384 & SHA2-512
        AUTHLIST=['1','3,','4','8','64221','65001']# Authentication: Pre-Shared Key, RSA Signatures, RSA Encryption, ECDSA Signature, Hybrid Mode and XAUTH
        GROUPLIST=['1','2','5','14','16']# Diffie-Hellman groups: 1, 2, 5, 14 & 16

    if LEN == 4:
        ENCLIST = ['1','2','3','4','5','6','7/128','7/192','7/256','8']
        HASHLIST = ['1','2','3','4','5','6']
        AUTHLIST = ['1','2','3','4','5','6','7','8','64221','64222','64223','64224','65001','65002','65003','65004','65005','65006','65007','65008','65009','65010']
        GROUPLIST = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18']

    for enc in ENCLIST:
        for hsh in HASHLIST:
            for auth in AUTHLIST:
                for grp in GROUPLIST:
                    t="--trans=%s,%s,%s,%s" % (enc,hsh,auth,grp)
                    translist.append(t)
    return translist

def check4AM(translist, IP): # Check for Aggressive Mode
    global AMC
    global nat
    global quick
    i=0
    AM=False
    AM2=False
    hashflag=False
    DeadPeer = False
    TLL=len(translist)

    for trans in translist:
        i+=1
        #sys.stdout.write("[>] Checking %s:                           \r" % (trans) )
        #sys.stdout.write("\r%s of %s: " % (i, TLL) )
        sys.stdout.write("\r%s: " % (i) )
        sys.stdout.flush()
        # (-M = Multiline (each payload shown on a separate line), -A = Aggressive Mode) #
        #  '-P' returns the response payloads including the responder hash (HASH_R) #
        strike="ike-scan -M -A --id=fakegroup " + trans + " " + nat + " " + IP + " -P" 
        cmd = subprocess.Popen(strike, shell=True, stdout=subprocess.PIPE)
        for line in cmd.stdout:
            if "Aggressive" in line:
                sys.stdout.write(" "*40+"\r")
                sys.stdout.flush()
                if AM==False: # AM Flag not yet set
                    AM=True
                    AMC=AMC+1
                    print "[+] " + line + "    (Validation: " + strike +")\n"
                    if quick: # -q option
                        print "[-] Not running implementation checks (-q)\n"
                        #return AM # uncomment this line to break out of the if statement, don't test other transforms and don't harvest the PSK hash
                    else:
                        checkImplemetation(trans, IP)
                else:
                    if AM2==False:
                        print"[-] Other transform options allowing Aggressive Mode handshakes on this host (from the T%s list of %s transforms):" % (LEN, TLL)
                        AM2=True
                    print("    (" + trans +")")
            if AM and not AM2:
                if hashflag:
                    print(line)
                    if DeadPeer == False:
                        # Patched versions respond to all requests with the DPD payload, but unpatched versions only return  
                        # a DPD payload when the group name is correct, providing a method for group ID enumeration.
                        print "[***] Dead Peer Detection was not reported - if the endpoint is an older CISCO device, it may be unpatched.\n"
                    print"[*] Note that unless the group ID is correct, the responder hash (hash_r) returned\n[\] from CISCO devices is an anti-enumeration feature, and will not be crackable.\n"
                    
                    hashflag=False
                if "hash_r" in line:
                    print "[+] RESPONDER HASH: ",
                    hashflag=True
                if "Dead Peer Detection" in line:
                    DeadPeer = True
    return AM

def checkImplemetation(trans, IP): # Guess VPN software provider
    imp="ike-scan -M " + trans  + nat + " " + " --showbackoff "+ IP
    sys.stdout.write("[>] Running implementation check (this can be slow...):    \r")
    sys.stdout.flush()
    cmd = subprocess.Popen(imp, shell=True, stdout=subprocess.PIPE)
    for line in cmd.stdout:
        if "Implementation" in line:
            sys.stdout.write(" "*40+"\r")
            sys.stdout.flush()
            print("[+] " + line + "    (Validation:" + imp + ")\n")

def ikescan(IP, translist, OnlyScanOpen):
    global nat
    global verbose
    eko("~"*40 + "\n[>] Testing " + IP + ":")
    if (not verbose):
        sys.stdout.write("[>] Testing " + IP + ":        \r")
        sys.stdout.flush()
    open500=chkport(IP)
    isOpen=False
    
    if nat=="":
        if open500:
            # print, even in quick mode.
            print "[+] " + IP + ":500/udp is open - checking for Aggressive Mode....\n"
            isOpen=True             
        else:
            strT="[!] " + IP + ":500/udp is open|filtered - "
            if OnlyScanOpen: 
                eko(strT + "not checking for Aggressive Mode...")
                #print "\n" + "~"*40
            else:
                print(strT + "checking for Aggressive Mode anyway (might take some time)...")
                isOpen=True # Flag to perform IKE scan

    else:
        isOpen=True

    if isOpen:
        AM=False
        AM=check4AM(translist, IP)
        sys.stdout.write("        \r")
        sys.stdout.flush()
        if AM:
            print "     \n[+] Conclusion: %s supports Aggressive Mode.\n" % (IP)
            if (not verbose):
                print "~"*40 
        else:
            tno = int(len(translist))
            print "     \n[+] Conclusion: %s did not return an Aggressive Mode handshake (%s transforms used).\n" % (IP, tno)

def eko(aradia):
    global verbose
    if verbose:
        print aradia

def h_alt():
    print "                 .__ __           "
    print "   ______ ___.__.|__|  | __ ____  "
    print "   \____ <   |  ||  |  |/ // __ \ "
    print "   |  |_> >___  ||  |    <\  ___/ "
    print "   |   __// ____||__|__|_ \\___  >"
    print "   |__|   \/             \/    \/ "

    print "                 .___ ____  __.___________ "
    print "   ______ ___.__.|   |    |/ _|\_   _____/ "
    print "   \____ <   |  ||   |      <   |    __)_  "
    print "   |  |_> >___  ||   |    |  \  |        \ "
    print "   |   __// ____||___|____|__ \/_______  / "
    print "   |__|   \/                 \/        \/  "


# ---------- MAIN --------------#

def heading():
    vlen=len(str(__version__))
    headlen=39
    n2=" "*int((headlen-20-vlen)/2)
    n3=""
    n4=(len(n2)*2 + vlen + 19)
    if headlen > n4:
        n3=" "*(headlen-n4)

    print "                 .___ ____  __.___________ "
    print "   ______ ___.__.|   |    |/ _|\_   _____/ "
    print "   \____ <   |  ||   |      <   |    __)_  "
    print "   |  |_> >___  ||   |    |  \  |        \ "
    print "   |   __// ____||___|____|__ \/_______  / "
    print "   |__|   \/                 \/        \/  "  
    print "   :" + "*"*(headlen-2) + ":"
    print "   :>>>==---%sv%s%s%s---==<<<:" % (n2,__version__,n2,n3)
    print "   :" + "*"*(headlen-2) + ":\n"

def shortheading():    
    n=35+len(str(__version__))
    print "\n" + ":" + "*"*n + ":"
    print ":>>>==---        pyIKE v%s        ---==<<<:" % __version__

def main():
    global quick
    global AMC
    global nat
    global LEN
    global verbose

    heading()
    
    chkroot()
    OnlyScanOpen=True
    quick=False
    AMC=0
    nat=""
    LEN=2
    verbose=False
    tnow = time.time()

    targets=[]
    targs=sys.argv[1:]

# check calls for usage/help
    for target in targs:
        if target.lower() in ("-h", "--h", "-help", "--help"):
            usage()
            sys.exit()

    print "\n[>] Checking options..."

# loop through cli options
    for target in targs:
        if target=="-v":
            if quick:
                print "[#] Overiding quick mode (-q)."
            quick=False
            verbose=True
            print "[+] Running in verbose mode (Report all attempts, even if Aggressive mode isn't found)."

        elif target=="-q":
            if verbose:
                print "[#] Overriding verbose mode (-v)."
            quick=True
            verbose=False
            print "[+] Running in Quick mode (No implementation checks)."

        elif target=="-nat":
            nat="--nat-t"
            print "[+] Running in NAT traversal mode (new default port = 4500/udp)."
 
        elif target=="-n":
            OnlyScanOpen=False
            verbose=True

        elif target[:2] == '-T': # Intensity
            TL = target[2]
            try:
                TI = int(TL)
                if TI>=1 and TI<=4:
                    LEN = TI
                else:
                    print "[!] Ignoring invalid intensity parameter %s (must be 1, 2, 3 or 4)." % target
            except:
                pass

        elif target[:3] == '-L:': # found a list
            filename = target[3:]
            # check file exists & can be opened
            validfile=True
            try:
                lines = [line.strip('\n') for line in open(filename)]
            except:
                print "[!] Cannot open file '%s'..." % (filename) 
                validfile=False
            if validfile:
                eko("[+] Appending the contents of '%s' to the target list..." % filename)
                for target in lines:
                    # check each list entry is a valid IP address
                    if validIP(target):
                        targets.append(target)
                    elif '/' in target: # found cidr target
                        cidrlist=returnCIDR(target)
                        for item in cidrlist:
                            if validIP(item):
                                targets.append(item)
                    else: 
                        print "[!] Invalid list entry '%s' was discarded... (not a valid IP address)" % target

        elif target[0] == "-":
            print "[!] Invalid command line argument (%r) was ignored..." % target

        elif '/' in target: # found cidr target
            cidrlist=returnCIDR(target)
            for item in cidrlist:
                targets.append(item)

        elif IPlist(target):
            addresslist=iprange(target)
            for item in addresslist:
                targets.append(item)

        elif validIP(target):
            targets.append(target)

        else:
             try: 
                x=(socket.gethostbyname(target)) # get IP from FQDN
                if x == '92.242.132.15':
                    raise Exception('BT Internet maps non-existent hosts to 92.242.132.15')
                eko("[+] FQDN '%s' resolves to %s" % (target, x))
                targets.append(x)
             except: 
                print "[!] Ignoring %s as it does not appear to be a valid target..." % (target)   
  

# Begin processing targets

    print "\n[>] Running pre-scan checks...."

    if len(targets)>0:
        
        if OnlyScanOpen:
            #print "[+] Checking all target 500/udp ports are open before attempting IKE scan (default)."
            print "[+] Checking all target ports are open before attempting IKE scan (default)."
            eko("    (use -n flag to override)")
        else:
            print "[+] Attempting IKE scan on all valid targets, even if 500/udp ports are not open."
            eko("    (-n flag set)")
        if LEN==1:
            print "[+] Using light intensity (-T1: 45 transforms + PSK (only) + DH 1, 2 & 5)."
        if LEN==2:
            print "[+] Using default intensity (-T2: 180 transforms + PSK, RSA, Hybrid & XAUTH + DH 1, 2, 5, 14 & 16 )."
        if LEN==3:
            print "[+] Using high intensity (-T3: 750 transforms + PSK, RSA, Hybrid, ECDSA & XAUTH + DH 1, 2, 5, 14 & 16)."
        if LEN==4:
            print "[+] Using all possible transforms (-T4: 23760 transforms + All Auths + DH 1-18)\n[***] NOTE: Using insane mode runs the risk of triggering an IDS."

        print # end of headers

        translist=gentrans(LEN)# generate a list of all applicable transforms
        print "[+] Using %r transforms on %r target(s).\n" % (int(len(translist)), int(len(targets)))

        if (not verbose):
            print "~"*40
        for target in targets: # MAIN LOOP 
            ikescan(target, translist, OnlyScanOpen)
        if quick:
            sys.stdout.write(" "*40 + "\n")
            sys.stdout.flush()
    else:
        print "\n" + "="*40 + "\n\n" + "[!] No valid targets provided."

    print "\n" + "="*75 + "\n"

    tfin = time.time()
    tdelta = int(tfin - tnow)
    print "[+] %s server(s) found supporting Aggressive Mode, in %s seconds.\n" % (AMC, tdelta)

    tf = (time.strftime("%H:%M:%S"))
    print "=== pyIKE finished at " + tf + " " + "="*(75-(23+len(tf))) +"\n\n"

# End Functions #

# --- Allow import without running the code --- #

if __name__ == "__main__":
    main()

# ------END------- #
