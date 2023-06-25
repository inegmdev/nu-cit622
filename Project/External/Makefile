force?=0

ifeq ($(force),1)
DOCKER_NO_CACH=--no-cache
else
DOCKER_NO_CACH=
endif


.PHONY : all stop build run attach root debug exploit

all : stop build run

stop:
	-docker stop sudo1
	sleep 1
	-docker rmi sudo1

build:
	docker build $(DOCKER_NO_CACH) -t sudo1 .

run:
	docker run --rm -v $(dirname "$0"):/pwd --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -d --name sudo1 -i sudo1

user:
	docker exec -u dev -it sudo1 /bin/bash

root:
	docker exec -u root -it sudo1 /bin/bash

exploit:
	docker exec -u dev -it sudo1 bash -c "cd /home/dev/exploit && python3 debug.py"
debug:
	docker exec -u dev -it sudo1 python3 /home/dev/debug/debug.py