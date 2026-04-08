# Credential-Access-Attacks
Threat hunting procedures for the MITRE ATT&amp;CK Tactic of Credential Access with Threat Hypothesis, Risk, visualizations, detections, hunting queries, and validation testing.

<img width="1321" height="796" alt="image" src="https://github.com/user-attachments/assets/d974f020-ac38-4764-befe-7be0b174be1d" />

Risk:

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning, often coupled with SMB relay, represent a critical, high-risk vulnerability in Windows-based networks. These techniques allow attackers on the same local network to intercept, spoof, and relay authentication traffic, leading to credential theft, unauthorized access, and lateral movement. 

Summary:

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.



