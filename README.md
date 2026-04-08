# Credential-Access-Attacks
Threat hunting procedures for the MITRE ATT&amp;CK Tactic of Credential Access with Threat Hypothesis, Risk, visualizations, detections, hunting queries, and validation testing.

<img width="1321" height="796" alt="image" src="https://github.com/user-attachments/assets/d974f020-ac38-4764-befe-7be0b174be1d" />

Risk:

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning, often coupled with SMB relay, represent a critical, high-risk vulnerability in Windows-based networks. These techniques allow attackers on the same local network to intercept, spoof, and relay authentication traffic, leading to credential theft, unauthorized access, and lateral movement. 

Summary:

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.


Threat Hunting Process

	1. Search for event ID 7045 which is a Windows System Log entry generated when a new service is installed on a local machine.

  2. Search for event id 4697 which is a Windows Security Log event for when a service is installed on the system.
   
  3. Something anomalous would be a PowerShell script running from Command line that is a deviation of baseline. If this was not a legitimate or scheduled service installation. The next step would be to review    the network traffic for this system in your SIEM enviornment for any other anomalous behavior or alerts going to or from Port UDP 5355 (LLMNR) and UDP 137 (NBT-NS). Also take a look at your Network IDS for the same time period.

  4. Review any modifications made to the RegistryPath hive HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast.

     "NOTE" The EnableMulticast registry key (HKLM\Software\Policies\Microsoft\Windows NT\DNSClient) is often missing because it is not created by default; it is only present if a Group Policy (GPO) has  specifically enabled or disabled LLMNR/Multicast DNS.

  5. Any modifications made to this registry key outside of normal change windows would be considered suspicious as adversary can change the setting in order to run the LLMNR poisoning.







