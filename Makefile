CC=gcc

all: build

build:
	mkdir -p bin/
# $(CC) -g -ggdb src/main.c -o bin/main -lcrypto -lcurl
	$(CC) -g -ggdb -D_DEBUG_PRINT src/bencoding.c  -o bin/bencoding -lcrypto -lcurl -lm

run: build
# ./bin/main
	./bin/bencoding
