# Report: Sudo Heap Overflow Baron Samedit (CVE-2021-3156)

![1687653479126](./image/OperatingSystemAttacks/1687653479126.png)

**Check list**

* [X] Try the exploit quickly
* [ ] Understand the CVE and what it's type, risk?

[CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit) | Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)

* [ ] How it is happened (overview)
* [ ] How the exploit happens
* [ ] Debugging in the `sudo` executable and the exploit (using the debugger if needed)
* [ ] Mitigation mechanism? Fix patch?
* [ ] Apply the patch and check the CVE impact.

## Motivation

This report discusses the CVE-2021-3156, also known as "Baron Samedit," is a critical vulnerability that affects the **sudo command**, a widely used utility in *inux systems. Discovered in January 2021, this vulnerability allows attackers to **escalate their privileges** and execute arbitrary commands as root without knowing the sudo command. This of course **expecting the adversary to have access to a local account in the sudoer group**. The score of the vulberability is (7.8) which is HIGH.
![1687680101260](image/OperatingSystemAttacks/1687680101260.png)

This vulnerability poses a **significant risk** to Linux systems, as sudo is commonly used to execute administrative tasks and manage system security. Exploiting CVE-2021-3156 requires local access or authenticated remote access, making it a valuable target for attackers who have already compromised a system or gained privileged access.

The **root cause** of the vulnerability lies in a **heap-based buffer overflow** within the sudo **command's argument** handling. By crafting a specially crafted input, an attacker can overwrite important data structures and gain unauthorized access.The vulnerability was quickly patched by the sudo development team. But if you don't have an updated versions of the some of Linux distros, you might be in risk.

## In this article

In this article we will:

1. **Setup the environment** for debugging and getting more information.
2. Describe the architecture and **how the vulnerability works**.
3. **Execute an actual exploit** for the CVE on a controlled **lab environment**.
4. Understand the fix and apply the patch on **the sudo package**.
5. Re-check the vulnerability and apply some OS security hardening mechanisms to avoid such vulnerabilities.

## Setup the environment

As per *[REF_ARTICLE_QUALYS]* , the latest environment setup that can have this vulnerability be tested on is:

* Distro: Ubuntu 20.04.1 LTS
* Sudo command version: Sudo version 1.8.31.
* Get the source code for sudo (exploit code is attached).
  Download from here - https://www.sudo.ws/dist/sudo-1.8.31p2.tar.gz

### Building the source code `sudo`

* Install prerequisites for the build
  `sudo apt-get update && sudo apt-get install -yq gcc make wget curl git vim gdb python3 python3-pip bsdmainutils`
* Get the version 1.8.31 for sudo (same default version in Ubuntu 20.04 without any security updates).
  `wget https://www.sudo.ws/dist/sudo-1.8.31p2.tar.gz && tar xvf sudo-1.8.31p2.tar.gz && cd sudo-1.8.31p2 `
* Building the source code of sudo package to be able to debug
  `export CFLAGS="-ggdb" && ./configure && make`
  ![1687682209720](image/OperatingSystemAttacks/1687682209720.png)

### Setup the debugging environment using VSCode

* Download VSCode from the official website.
* Install it using `sudo dpkg -i code_1.79.2-1686734195_amd64.deb`.
* Go to the source folder `sudo-1.8.31p2` and call `code .` this will open VSCode for this folder.
* Install [extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools-extension-pack) "C/C++ Extension Pack" from Microsoft using the command pallete.
* 
* Identify the output directories (from Makefile syntax, all the output binaries are inside `.libs` folder), here are the output dirs:
  ![1687684369986](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/inegm/_master/2023/nu-cit622.git/Project/Report/image/OperatingSystemAttacks/1687684369986.png)
  Here's an example of the `sudo` binary
  ![1687684531869](image/OperatingSystemAttacks/1687684531869.png)
* 

## Understanding the attack

### Root cause of the vulnerability

#### Overview of the vulnerability

It is a **heap-based buffer overflow vulnerability** found in the sudo command, a widely used utility in Linux systems. The vulnerability is caused by an integer overflow when calculating the size of a user-controlled string, which leads to a buffer overflow condition. This allows an attacker to overwrite important data structures and execute arbitrary code with root privileges.

## Resources

1. *[REF_ARTICLE_QUALYS]* [CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit) | Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)

## Appendices

### Installing ProcMon for Linux

[ProcMon-for-Linux/INSTALL.md at main · Sysinternals/ProcMon-for-Linux · GitHub](https://github.com/Sysinternals/ProcMon-for-Linux/blob/main/INSTALL.md)

### Debugging Dockerized app using Visual Studio Code

[Debug an app running in a Docker container (visualstudio.com)](https://code.visualstudio.com/docs/containers/debug-common)










## Attack choice

### Understanding the overview of the attack

### How to perform this attack (PoC)

### Dive deep in tha attack mechanism

## Mitigation mechanism

### Overview of the mitigation/defence mechanism

### Applying the mechanism

### Check if the same attack can be prevented after applyting the mechanism

* 
* **Understanding attack techniques** : Researchers delve into the intricacies of operating system attacks, analyzing how vulnerabilities can be exploited, and studying attack patterns and methodologies used by adversaries.
* **Developing robust defenses** : Efforts are focused on designing and implementing effective security mechanisms to protect against attacks. This involves creating innovative techniques such as sandboxing, access control mechanisms, secure boot processes, and intrusion detection systems.
* **Evaluating and enhancing security** : Researchers conduct rigorous evaluations of existing security mechanisms and identify areas for improvement. This includes examining the effectiveness, performance, and usability of defenses, as well as proposing enhancements to ensure robust protection.

The research project evaluation: Pick the Project/attack/defense/security technique related to the operating system (as of your interest).

* **Research novelty and Analysis Quality (40%)**

  * Research how Project/attack/defense/security technique internally work. This involve using tools such as debuggers/API monitor to develop understanding how the subject of the research interacts with the operating system and what artifacts left behind (similar to your research in the Password Dump using Mimikatz)
  * Analysis novelty require showing evidence of debugging/analysis of the attack in your own. Avoid copy/paste/rewrite from public blog posts/etc
* **Proof Of Concept (30%)**

  * Develop PoC in C/C++ that explain (for example) how the attack can work? How the defense mechanism can be bypassed? How the defense mechanism can be disabled/enabled/manipulated?
* **Final Report (30%)**

  * The final report should be around 20 to 30 pages that have detailed analysis of the research subject, screen shot explaining how you debugged/analyzed the research/attack/defense/techniques and output of your analysis.
  * Any other additional logs you want to share (i.e. procmon logs/OS events/logs/etc)
