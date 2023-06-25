# Fetch the Ubuntu version that has this issue
FROM ubuntu:20.04

# ENV LC_CTYPE C.UTF-8: This ENV instruction sets the environment 
# variable LC_CTYPE to C.UTF-8. The LC_CTYPE environment variable
# specifies the character encoding and localization settings for 
# the current locale. Setting it to C.UTF-8 ensures that the UTF-8
# encoding is used, which is commonly used and supports a wide range
# of characters.
# This particular environment variable is often set to avoid any 
# potential issues related to character encoding or locale differences
# when running commands or building software within the Docker image.
ENV LC_CTYPE C.UTF-8

# The DEBIAN_FRONTEND variable is commonly used in Debian-based images
# during package installation to prevent interactive prompts. Setting 
# it to noninteractive ensures that no prompts are displayed during 
# package installation, allowing the Docker build process to proceed 
# without manual intervention.
ARG DEBIAN_FRONTEND=noninteractive

# Updating and installing git, gdb, python3 vim and useful tools that we'll need
RUN apt-get update && apt-get install -yq gcc make wget curl git vim gdb python3 python3-pip bsdmainutils

# Send the source files from host machine to docker
COPY ./sudo-1.8.31p2 /root/sudo-1.8.31p2

# Compile and run the sent sudo package
WORKDIR /root/sudo-1.8.31p2
RUN echo "\n\n\nBuilding and installing sudo package from host" 
RUN pwd && export CFLAGS="-ggdb" && ./configure && make && make install

# Adding new user (dev) account
RUN useradd -ms /bin/bash dev

# Differentiate between the bash prompt symbol in dev / root
RUN echo 'export PS1="\[\e]0;\u@\h: \w\a\]\[\033[01;31m\]\u\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]# "' >> /root/.bashrc
RUN echo 'export PS1="\[\e]0;\u@\h: \w\a\]\[\033[01;32m\]\u\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ "' >> /home/dev/.bashrc

# Set the working home directory
WORKDIR /home/dev

# Building the exploit
COPY ./exploit /home/dev/exploit
WORKDIR /home/dev/exploit/libnss_X
RUN gcc -shared -o X1234.so.2 -fPIC X1234.c
WORKDIR /home/dev/exploit
# Done
RUN echo "Done and ready for exploiting and debugging!"
