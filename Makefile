CC=gcc

all: build

build:
	mkdir -p bin/
	$(CC) -g -ggdb src/main.c -o bin/main -lcrypto

run: build
	./bin/main
