# LAB 2: Packet Slueth

Jake Jarvis (jjarvi01)
COMP 116


## set1.pcap

1. How many packets are there in this set?

     465 packets.

2. What protocol was used to transfer files from PC to server?

     FTP was used.

3. Briefly describe why the protocol used to transfer the files is insecure?

     Everything was transmitted in plaintext -- the username, password, data, and every single command.

4. What is the secure alternative to the protocol used to transfer files?

     FTPS adds TLS/SSL encryption over the FTP transaction (analogous to HTTP vs. HTTPS). SFTP (SSH File Transfer Protocol) can also be used to transfer files securely if SSH is available.

5. What is the IP address of the server?

     192.168.1.4

6. What was the username and password used to access the server?

     username: broken
     password: r3wt

7. How many files were transferred from PC to server?

     4 files

8. What are the names of the files transferred from PC to server?

     48b.jpg
     522.jpg
     639.jpg
     b29.jpg


## set2.pcap

10. How many packets are there in this set?

     4 packets.

11. To what service or protocol did the sender use to covertly send images? Briefly describe your answer.

     The packets were sent over HTTP/Port 80.

12. Briefly describe how you were able to reconstruct the image from the packets.

     I was not successful in doing this but here is what I tried: I followed the TCP Stream in Wireshark and exported the raw data to a file. I then opened the file in a HEX editor and attempted to add the HEX headers for JPGs, PNGs, GIFs, and more (https://digital-forensics.sans.org/media/hex_file_and_regex_cheat_sheet.pdf) but the file still wouldn't open in any image editor.

13. Who is in the picture?

     


## set3.pcap

14. How many packets are there in this set?

     80,525 packets.

15. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.

     I found two plaintext username/password pairs -- one through HTTP and one through IMAP.

16. Briefly describe how you found the username-password pairs.

     I ran ettercap and grepped the results with "PASS:". I also tried using dsniff but that didn't pick up the IMAP password that ettercap did. 

17. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name if possible (e.g., google.com), and port number.

     USERNAME: nab01620@nifty.com
     PASSWORD: Nifty->takirin1
     PROTOCOL: IMAP (port 143)
     SERVER:   210.131.4.155

     USERNAME: nagiosadmin
     PASSWORD: Vid30Plu$!
     PROTOCOL: HTTP (port 80)
     SERVER:   12.227.41.123

18. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.

     Both seem to be legitimate. The IMAP login appears to have worked because packet #48056 reads "Response: 2 OK LOGIN Ok." from the IMAP server. The HTTP login also appears successful by looking at what happened after packet #67191 (HTTP 401 Auth Required) -- the next response from the web server was a 200 OK status and it continued to load pages like main.php, side.php, and the stylesheets which would not have been allowed with an incorrect username/password pair. But, as we discussed in class, this can all be spoofed (albeit with a lot of effort) so we can never be 100% sure.


## set4.pcap

19. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.

     I only found one plaintext username/password pair.

20. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name if possible (e.g., google.com), and port number.

     USERNAME: wanderson@e-netsecurity.com.br
     PASSWORD: @1052wmc12$$
     PROTOCOL: IMAP (port 143)
     SERVER:   177.39.17.52

21. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.

     The IMAP pair appears to be legitimate. I know this by looking at packet #15980 which says "42 OK LOGIN Ok", and then the following packets discussing the person's Inbox. However, as mentioned above, this can be spoofed.

22. Provide a listing of all IP addresses with corresponding hosts (hostname + domain name) that are in this PCAP set. Describe your methodology.

     See file IPs_uniq.txt for results. 

     I ran two commands:

     > tshark -r set4.pcap -T fields -e ip.src -e dns.qry.name | sort | uniq    # list source IPs & domain name, sort, and remove duplicate lines
     > tshark -r set4.pcap -T fields -e ip.dst -e dns.qry.name | sort | uniq    # list destination IPs & domain name, sort, and remove duplicate lines

     ...and then merged the results of both into one file (with duplicate lines removed). I noticed a lot of random domains resolving to 192.168.1.1 -- I left them in because I'm not positive, but I believe this is caused by some ad-blockers.

## General Questions

23. How did you verify the successful username-password pairs?

     I verified username/password pairs by starting at the packet where I found the pair and examining the following packets. For the HTTP logins, I looked for things like HTTP 200 OK responses followed by files that would normally go along with a fully-loaded website (stylesheets, etc). For the IMAP logins, I was able to follow the server responding with things like "LOGIN OK" and the names of the user's mailboxes (Inbox, Sent, Trash, etc). 

24. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?

     Always look for the HTTPS (or the little green lock) in the address bar when submitting any passwords or sensitive information. In a perfect world, to be very safe, do not handle ANY personal data when on public Wi-Fi networks that are not locked down with WPA encryption. If this is absolutely necessary, use a VPN. When in doubt, wait until you get home.
