# pyike
An ike-scan wrapper script in Python to check VPN endpoint support for Aggressive Mode, with various Authorisation parameters.  
*Pre-requisites: Python 2.7.x, Nmap, Ike Scan (https://github.com/royhills/ike-scan)*
<ul>
<li>Generates Transforms on the fly, as needed  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T1 (light): 45 transforms + PSK (only) + DH 1, 2 & 5  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T2 (default): 180 transforms + PSK, RSA, Hybrid & XAUTH + DH 1, 2, 5, 14 & 16  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T3 (high): 750 transforms + PSK, RSA, Hybrid, ECDSA & XAUTH + DH 1, 2, 5, 14 & 16  <br>
&nbsp;&nbsp;&nbsp;&nbsp;-T4 (insane): 23760 transforms + All Auths + DH 1-18  <br>
<li>Allows a choice of intensities (varying numbers of transforms, hashes and DH groups). Use <i>-h</i> for <b>help</b> & <b>usage</b>.
<li>Checks single or multiple targets (individual targets, ranges, lists or CIDR) for UDP port 500 open and ike-scans them in aggressive mode if they are (it prints the command to validate this) and prints the responder hash (with caveat). 
<li>Checks the implementation fingerprint (guesses the vendor).
<li>Checks to see if port 4500 is open and suggests nat-t if it is.
<li>Checks to see if Dead Peer Detection is reported (missing for an incorrect group name from an unpatched ASA firewall)
</ul>

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
   :>>>==---       v1.2.9        ---==<<<:
   :*************************************:


[>] Checking options...

[>] Running pre-scan checks....
[+] Checking all target ports are open before attempting IKE scan (default).
[+] Using light intensity (45 transforms (-T1) with PSK only).

[+] Using 45 transforms on 1 target(s).

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[+] 10.100.140.35:500/udp is open - checking for Aggressive Mode....

[+] 10.100.140.35       Aggressive Mode Handshake returned
  (Validation: ike-scan -M -A --id=fakegroup --trans=1,2,1,2  10.100.140.35 -P)
[+] 10.100.140.35       Implementation guess: Cisco VPN Concentrator or PIX 7.0
    (Validation:ike-scan -M --trans=1,2,1,2  --showbackoff 10.100.140.35)
[+] RESPONDER HASH:  
    ef783d4e396cfc346355cbfe34e4453a1229516afeef5d6a0e2d396d5401c8bbfd94e4a0ef54
    4867a3425c233e8215b0fa254e78fa91f00cb02703377d1efc3883ad1c8af19532a3fb478818
    31dfcd25ed3ec3632f594dc0e14060249811197673bb6bf30954e4c4f1c8bb84ae9461ffb5eb
    751f3489a75f391b0e38b347619e:351b5a2fe9d637a8b177cca1ee82c763226b5e21bf008af
    72540b983ac9e3f946171261a6dd7bf30ea44fcbac6626e6729f5360dc7c7f6734063e3664fb
    9f51b1d6d5561da028b51d3aa353a213b1c5de46b0873354de6bd5b157a8ef85158155f6e174
    7a71bfabedad085e43f1093f4838856de5e9e3aeede032bd0d6a47a31:4afd7b2ce95004cb:
    9e0f7334f61a4851:00000001000000010000002c01010001000000240101000080010001800
    200028003000180040002800b0001000c000400007080:01110000c3c29203:14c66ec47ed4c
    011c80282380817304f60e7a793:c1d58588f72ed98090b9f754715b55703c7b008e:0499668
    74047a033280ff231a366c1cd9cf1a0ce

[*] Note that unless the group ID is correct, the responder hash (hash_r) returned
[/] from CISCO devices is an anti-enumeration feature, and will not be crackable.

[-] Other transform options allowing Aggressive Mode handshakes on this host (from the T1 list of 45 transforms):
    (--trans=5,2,1,2)
    (--trans=7/128,2,1,2)                   
    (--trans=7/192,2,1,2)                   
            
[+] Conclusion: 10.100.140.35 supports Aggressive Mode.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

===========================================================================

[+] 1 server(s) found supporting Aggressive Mode.

=== pyIKE finished at 16:07:10 ============================================
```
