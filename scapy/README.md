# LAB 4: Scapy

Jake Jarvis (jjarvi01)
COMP 116

Hours spent: ~10 hours


### Implemented correctly:
- Image reconstruction should be implemented with no problems
- Alarm should both sniff live networks and read PCAP files in correctly, as well as handle any command line arguments and print nicely formatted alarm details

### Not implemented:
- Masscan detection not implemented
- Shellshock detection not implemented
- Nikto scan has part of the User-Agent hard-coded in ("Mozilla/5.00") -- this will probably be changed by the developer sooner or later


### Questions:

#### 1. Are the heuristics used in this assignment to determine incidents "even that good"?

NO! Besides the various Nmap scans, I would not have 100% confidence in any of the other tests being able to perfectly catch every incidence in real-world applications. Credit cards can be in many different formats, phpMyAdmin can be installed in a different folder, plaintext passwords can be submitted in fields named many different things, etc... Additionally, alarm fatigue would be a real issue. When a single particular scan sounds literally thousands of alarms (*cough* Nikto *cough*), the person using this script to monitor a network will have less and less of a sense of urgency when hearing the alarm every time a false positive is raised (or even receiving an excessive reaction to a legitimate threat from the alarm).

#### 2. If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?

I think a prioritization of the alarms would be helpful in contexts with large amounts of traffic. A "louder" alarm should be sounded for a credit card number or cleartext password verses a simple port scan. I would also want to check the credibility of the information found. As we saw in the Defcon PCAPs, it can be valuable to follow the trail of packets a little farther down the road to see if a cleartext password actually worked and led to anything interesting.