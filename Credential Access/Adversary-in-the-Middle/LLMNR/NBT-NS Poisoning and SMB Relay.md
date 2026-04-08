Credential Access: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
https://attack.mitre.org/techniques/T1557/001/

<img width="1442" height="839" alt="image" src="https://github.com/user-attachments/assets/bfeeef96-e261-463a-812b-5dd1e0b1241e" />


Risk:

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning, often coupled with SMB relay, represent a critical, high-risk vulnerability in Windows-based networks. These techniques allow attackers on the same local network to intercept, spoof, and relay authentication traffic, leading to credential theft, unauthorized access, and lateral movement. 

Summary:

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.

Threat Hypothesis:

The adversary has performed legacy broadcast protocol poisoning attacks to intercept network traffic from domain hosts and capture Net-NTLMv2 hashes.

Threat Hunting Process:

  1. Search for event ID 7045 which is a Windows System Log entry generated when a new service is installed on a local machine.

  2. Search for event id 4697 which is a Windows Security Log event for when a service is installed on the system.
   
  3. Something anomalous would be a PowerShell script running from Command line that is a deviation of baseline. If this was not a legitimate or scheduled service installation. The next step would be to review    the network traffic for this system in your SIEM enviornment for any other anomalous behavior or alerts going to or from Port UDP 5355 (LLMNR) and UDP 137 (NBT-NS). Also take a look at your Network IDS for the same time period.

  4. Review any modifications made to the RegistryPath hive HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast.

     "NOTE" The EnableMulticast registry key (HKLM\Software\Policies\Microsoft\Windows NT\DNSClient) is often missing because it is not created by default; it is only present if a Group Policy (GPO) has  specifically enabled or disabled LLMNR/Multicast DNS.

  5. Any modifications made to this registry key outside of normal change windows would be considered suspicious as adversary can change the setting in order to run the LLMNR poisoning.
  
  6. If you have CrowdStrike Falcon a catch all query can be run using the following query:
     
     1 #event_simpleName="ProcessRollup2"
     2 event_platform="Win"
     3 | Technique = "Adversary-in-the-Middle"

  7. Use the CrowdStrike Query Builder to look for artifacts of LLMNR poisioning tools Impacket, Responder and Inveigh

  <img width="1531" height="512" alt="image" src="https://github.com/user-attachments/assets/9aae5792-74b3-4e10-98ff-7350ee3a9e6a" />

  8. Vendor Agnostic Hunting Query
      (Event ID = 4697 OR Event ID = 7045) AND (Destination Port 5355 OR Destination Port 137 OR Multicast 224.0.0.252) AND Registry Hive Mod HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast

  9. Post execution of the LLMNR poisoning the PCAP will display the attacker IP making LLMNR connections to the victim IP and Multicast IP 224.0.0.25 and Destination port 5355.

     <img width="1571" height="916" alt="image" src="https://github.com/user-attachments/assets/c36be0ce-6fd6-4b73-8ed1-cb7dd4602f5a" />

 10. Validate your detection queries.

Disclaimer:  
This material is provided solely for testing and educational purposes. Do not perform any form of penetration testing, security scanning, or system exploitation without explicit, written authorization from the system owner. Unauthorized testing is illegal and unethical.

     https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1557.001/T1557.001.md

     <img width="1013" height="477" alt="image" src="https://github.com/user-attachments/assets/147ceda2-ccd1-4bd3-86d8-73ecac329a74" />


11. To reproduce the attack scenario using Responder open a Kali instance then open a terminal in sudo.

12. In the terminal type sudo responder -I eth0 -v

13. On the target windows system attempt to map to a non-existent file share.

14. Collect the NTLMv2 hash to crack offline

15. Extract the entire hash value and save it to hash.txt

19. Execute John the Ripper "john --form=md5--wordlist=/usr/share/wordlists/rockyou.txt hash.txt"

20. Confirm using Wireshark on Target system.

    <img width="1571" height="916" alt="image" src="https://github.com/user-attachments/assets/c36be0ce-6fd6-4b73-8ed1-cb7dd4602f5a" />
