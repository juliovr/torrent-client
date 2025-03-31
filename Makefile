CC=gcc

all: build

build:
	mkdir -p bin/
# $(CC) -g -ggdb src/main.c -o bin/main -lcrypto -lcurl
	$(CC) -g -ggdb src/bencoding.c  -o bin/bencoding

run: build
# ./bin/main
	./bin/bencoding
