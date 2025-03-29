CC=gcc

all: build

build:
	mkdir -p bin/
	$(CC) -g -ggdb src/main.c -o bin/main

run: build
	./bin/main
