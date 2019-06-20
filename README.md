# pyike
A script to check VPN endpoint support for Aggressive Mode, with various Authorisation parameters.
# Generates Transforms on the fly, as needed.
# Allows a choice of intensities (varying numbers of transforms, hashes and DH groups). Use -h for help.
# Checks single or multiple targets for UDP port 500 open and ike-scans them in aggressive mode if they are (it prints the command to validate this) and prints the responder hash (with caveat). 
# Checks the implementation fingerprint (guesses the vendor).
# Checks to see if port 4500 is open and suggests nat-t if it is.
# Checks to see if Dead Peer Detection is reported (missing for an incorrect group name from an unpatched ASA firewall)
