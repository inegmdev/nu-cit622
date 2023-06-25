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
build: to_be_replaced=$(shell realpath .)
build:
	cd ./sudo-1.8.31p2 && export CFLAGS="-ggdb" && ./configure && make
	# Re-link the installation paths for the docker
	sed -E "s;$(to_be_replaced);/root;g" -i $(shell grep ./sudo-1.8.31p2 -rl "$(to_be_replaced)" --include=*.la --include=*.status --include=*.log | xargs echo )
	docker build $(DOCKER_NO_CACH) -t sudo1 .

run:
	docker run --rm -v $(dirname "$0"):/pwd --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -d --name sudo1 -i sudo1

user:
	docker exec -u dev -it sudo1 /bin/bash

root:
	docker exec -u root -it sudo1 /bin/bash

exploit:
	docker exec -u dev -it sudo1 bash -c "cd /home/dev/exploit && python3 exploit.py"
debug:
	docker exec -u dev -it sudo1 python3 /home/dev/debug/debug.py