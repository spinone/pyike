# pyike
An ike-scan wrapper script in Python to check VPN endpoint support for Aggressive Mode, with various Authorisation parameters.  
*Pre-requisites: Python 2.7.x, Nmap, Ike Scan (https://github.com/royhills/ike-scan)*
<ul>
<li>Allows a choice of intensities (varying numbers of transforms, hashes and DH groups)  
<li>Generates Transforms on the fly, as needed. Use <i>-h</i> for <b>help</b> & <b>usage</b>.  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T1 (light): 45 transforms + PSK (only) + DH 1, 2 & 5  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T2 (default): 180 transforms + PSK, RSA, Hybrid & XAUTH + DH 1, 2, 5, 14 & 16  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T3 (high): 750 transforms + PSK, RSA, Hybrid, ECDSA & XAUTH + DH 1, 2, 5, 14 & 16  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T4 (insane): 23760 transforms + All Auths + DH 1-18  <br>
<li>Quick scan mode (-q) for rapid assessment.
<li>Checks single or multiple targets (individual targets, ranges, lists or CIDR) for UDP port 500 open and ike-scans them in aggressive mode if they are (it prints the command to validate this) and prints the responder hash (with caveat). 
<li>Checks the implementation fingerprint (guesses the vendor).
<li>Checks to see if port 4500 is open and suggests nat-t if it is.
<li>Checks to see if Dead Peer Detection is reported (missing for an incorrect group name from an unpatched ASA firewall)  
</ul>  

Run as **root** ( or, in Linux, add the following to the user's .bashrc file):  
```
# PyIKE  
alias pyike='sudo python /home/user/git/pyike/pyike.py '  
```
Where **/home/user/git/pyike** is the path to the script (note the trailing space after .py)  
Invoking the script then only needs *pyike [targets] [options]* from any location.   


**Example Output:**
```
sudo python pyike.py 10.100.140.35 -T1
                 .___ ____  __.___________ 
   ______ ___.__.|   |    |/ _|\_   _____/ 
   \____ <   |  ||   |      <   |    __)_  
   |  |_> >___  ||   |    |  \  |        \ 
   |   __// ____||___|____|__ \/_______  / 
   |__|   \/                 \/        \/  
   :*************************************:
   :>>>==---       v1.3.0        ---==<<<:
   :*************************************:


[>] Checking options...

[>] Running pre-scan checks....
[+] Checking all target ports are open before attempting IKE scan (default).
[+] Using light intensity (-T1: 45 transforms + PSK (only) + DH 1, 2 & 5).

[+] Using 45 transforms on 1 target(s).
[+] Estimated time to complete: 80 seconds (approx).

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[+] 10.100.140.35:500/udp is open - checking for Aggressive Mode....

[+] 10.100.140.35       Aggressive Mode Handshake returned
    (Validation: ike-scan -M -A --id=fakegroup --trans=1,2,1,2  10.100.140.35 -P)

[+] 10.100.140.35       Implementation guess: Cisco VPN Concentrator or PIX 7.0
    (Validation:ike-scan -M --trans=1,2,1,2  --showbackoff 10.100.140.35)

[+] RESPONDER HASH: 
c8d2f2ed8e3a3a09e7824de49ef9398c9ecd2ea185282b5601c9a0e94ca59695492eb76007f026f93
353d4a666bae77f527bdf444fbfbe2905e583f4dea45a0e2a28665dce30d2fd3b2bb54bb6c41f4c2c
9ca1f07535fccc50ed2b794cc2c656d94feb9e41c6c6ffa3162feb3453ecfe2d2df202f07f9b9c468
0fe4dfc3bf2d0:13fb25ddb046d0beec24002425907b64e04b54098d6b3251f28f0883629db66b75c
4a593c4e8e1cdf0a67711c912305b59475d7a4b94d8ec1a21bf9977fc50c981ad77f0ba63229fd3ef
671fa0c9020facf7252d938d7cca50a4e2893809d0804f4482a6864805635d4e4cd5e67f3fe4e7579
a6163fcc3bb2d03e2d17880a430:ca63f2a6a888d960:1a2738d64c632c6f:
00000001000000010000002c010100010000002401010000800100018002000280030001800400028
00b0001000c000400007080:01110000c3c29203:b256a432d31fb66df75b65911b407de632d9d3e4:
4529d274bbb87df8a083d7833c1ec79444f3c253:7c4dfe3c8993ac3a40a4bea6604590ad6aedfafe

[*] Note that for CISCO devices, unless the group ID is correct, the responder hash (hash_r)
[\] returned from the endpoint is an anti-enumeration feature, and will not be crackable.

[-] Other transform options allowing Aggressive Mode handshakes on this host 
    (from the T1 list of 45 transforms):
    (--trans=5,2,1,2)
    (--trans=7/128,2,1,2)                   
    (--trans=7/192,2,1,2)                   
            
[+] Conclusion: 10.100.140.35 supports Aggressive Mode.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

===========================================================================

[+] 1 server(s) found supporting Aggressive Mode, in 82 seconds.

=== pyIKE finished at 14:36:02 ============================================
```
