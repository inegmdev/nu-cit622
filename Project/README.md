# Final Project: Operating System Attacks, Defenses and Security Mechanism

**Research in Operating System Attacks, Defenses, and Security Mechanisms**: focuses on understanding and mitigating security vulnerabilities and threats within computer operating systems. Operating systems form the foundation of modern computing, and their security is crucial in safeguarding sensitive data, protecting against unauthorized access, and preventing malicious activities.

This project aims at exploring various attack vectors, such as privilege escalation, buffer overflows, code injection, and more, to develop understanding how those vulnerabilities that can be exploited by attackers. Researchers strive to develop effective defense mechanisms and security measures to mitigate these threats and enhance the overall security posture of operating systems.

Key objectives of project include:

* **Understanding attack techniques** : Researchers delve into the intricacies of operating system attacks, analyzing how vulnerabilities can be exploited, and studying attack patterns and methodologies used by adversaries.
* **Developing robust defenses** : Efforts are focused on designing and implementing effective security mechanisms to protect against attacks. This involves creating innovative techniques such as sandboxing, access control mechanisms, secure boot processes, and intrusion detection systems.
* **Evaluating and enhancing security** : Researchers conduct rigorous evaluations of existing security mechanisms and identify areas for improvement. This includes examining the effectiveness, performance, and usability of defenses, as well as proposing enhancements to ensure robust protection.

There have been several **research projects and security mechanisms** developed specifically for Microsoft Windows operating system (and other project develop generally for all Operating systems). **Here are a few examples (not limited):**

* Control Flow Guard (CFG)
* Windows Defender Application Control (WDAC):
* Enhanced Mitigation Experience Toolkit (EMET)
* Windows Defender Exploit Guard
* Microsoft Defender Antivirus
* DEP/ASLR/Heap Protection, and many other memory protection techniques. etc
* Protected Process (PPL)
* And many more.

The research project evaluation: Pick the Project/attack/defense/security technique related to the operating system (as of your interest).

* **Research novelty and Analysis Quality (40%)**

  * Research how Project/attack/defense/security technique internally work. This involve using tools such as debuggers/API monitor to develop understanding how the subject of the research interacts with the operating system and what artifacts left behind (similar to your research in the Password Dump using Mimikatz)
  * Analysis novelty require showing evidence of debugging/analysis of the attack in your own. Avoid copy/paste/rewrite from public blog posts/etc
* **Proof Of Concept (30%)**

  * Develop PoC in C/C++ that explain (for example) how the attack can work? How the defense mechanism can be bypassed? How the defense mechanism can be disabled/enabled/manipulated?
* **Final Report (30%)**

  * The final report should be around 20 to 30 pages that have detailed analysis of the research subject, screen shot explaining how you debugged/analyzed the research/attack/defense/techniques and output of your analysis.
  * Any other additional logs you want to share (i.e. procmon logs/OS events/logs/etc)
* **References** :
* Windows Internals books
* Linux Kernel internals/documentation
