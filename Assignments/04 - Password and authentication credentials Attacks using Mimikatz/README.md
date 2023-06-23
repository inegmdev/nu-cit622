# Assignment#4: 🔐 Password and authentication credentials Attacks using Mimikatz

## Assignment Details

### What is Mimikatz

Mimikatz is a well-known tool test the security of a system. It is primarily used to extract password hashes, plaintext passwords, and other authentication credentials from a Windows system's memory. The tool is designed to exploit weaknesses in the Windows security model and can be used to escalate privileges and perform other malicious actions.

### How it works

To dump password and credentials, Mimikatz uses a technique called "pass-the-hash." This technique involves extracting password hashes from memory and then using them to authenticate with other systems without the need for the actual password. This means that even if the password is changed, an attacker can still use the hash to authenticate with other systems.

Mimikatz also has the ability to extract plaintext passwords from memory by scanning for them in clear text format. This is possible because Windows often stores passwords in plain text format in memory, making them vulnerable to extraction by tools like Mimikatz.

### What is expected in the assignment?

In this assignment you are asked to do a thoroughly analysis of Mimikatz and how it works. Starts from the Mimikatz source code on Github:

- Compile Mimikatz from source code.
- Run Mimikatz binariy (In a Virtual machine) and monitor the API calls using you user mode hooking tools ( Assignment 3) and/or ProcessExporer/ProcessMonitor.
- Write an analysis report that shows the following:
  - High level outline on how Mimikatz works and what API it calls to access Lsass process
  - How the “Pass the hash” technique works and where in the code this technique is implemented and how it implemented.
  - When you run Mimikatz on a victim virtual machine, what artifacts it leaves behind?
    - What files being dropped on a system?
    - What process is created, and victims process being accessed?
    - Any other important artifacts?

### Tool documentation

https://github.com/gentilkiwi/mimikatz

#### Assignment deliverables

- Full and detailed analysis report of min 10 pages and no longer than 20 pages.
- Screenshot Mimikatz running in command line and output the and how to dump user pass/credentials.

## Tasklist

* [X] Compile Mimikatz from source code.
* [X] Disable security on the VM.
* [ ] Run Mimikatz binariy (In a Virtual machine) and monitor the API calls.
* [ ] Write analysis report that shows:
  * [ ] High level outline how mimikatz work.
  * [ ] What API it calls to access `lsass` process.
  * [ ] How "pass-the-hash" technique works.
  * [ ] Where in the mimikatz tool this code is implemented and how it works.
  * [ ] What are the artifacts that mimikatz leave on a victim virtual machine
    * [ ] What is being dropped.
    * [ ] What process is created.
    * [ ] Any other important artifacts.
  * [ ] Screenshots mimikatz running in command line and the output, and how to dump user/pass credentials.

### Resources

* [REF_MIMIKATZ_TUT] [Dumping User Passwords from Windows Memory with Mimikatz | Windows OS Hub (woshub.com)](https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/)
* [If you grant somebody SeDebugPrivilege, you gave away the farm - The Old New Thing (microsoft.com)](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113)
