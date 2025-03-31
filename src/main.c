#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef struct string string;
struct string {
    char *characters;
    size_t length;
};

string new_string(char *characters, size_t length)
{
    return (string) {
        .characters = characters,
        .length = length,
    };
}


typedef struct Tokenizer Tokenizer;
struct Tokenizer {
    u8 *start;
    u8 *current;
    size_t size;
};

Tokenizer tokenizer;

typedef struct Info Info;
struct Info {
    u64 length;
    string name;
    u32 piece_length;
    string pieces;
};

typedef struct Torrent Torrent;
struct Torrent {
    string announce;
    string comment;
    string created_by;
    s32 creation_date;
    u8 info_hash[SHA_DIGEST_LENGTH];
    Info info;
};

void print_ident(int size)
{
    while (size--) {
        printf(" ");
    }
}

static int calculate_string_length()
{
    int string_length = atoi(tokenizer.current);

    while (*tokenizer.current != ':') {
        tokenizer.current++;
        tokenizer.size--;
    }
    tokenizer.current++;
    tokenizer.size--;

    return string_length;
}

static u64 get_number()
{
    u64 num = strtoull(tokenizer.current, NULL, 0);
    
    while (*tokenizer.current != 'e') {
        tokenizer.current++;
        tokenizer.size--;
    }
    tokenizer.current++;
    tokenizer.size--;

    return num;
}

typedef enum TokenType TokenType;
enum TokenType {
    TOKEN_TYPE_NUMBER,
    TOKEN_TYPE_STRING,

    TOKEN_TYPE_COMPLETED,

    TOKEN_TYPE_COUNT,
};

static char *get_token_type_name(TokenType type)
{
    switch (type) {
        case TOKEN_TYPE_NUMBER: return "TOKEN_TYPE_NUMBER";
        case TOKEN_TYPE_STRING: return "TOKEN_TYPE_STRING";
        case TOKEN_TYPE_COMPLETED: return "TOKEN_TYPE_COMPLETED";
    }

    return "UNKNOWN";
}

typedef struct Token Token;
struct Token {
    TokenType type;
    union {
        u64 num_value;
        string string_value;
    };
};

static Token get_token()
{
    Token token = {0};
    token.type = TOKEN_TYPE_COMPLETED;

    while (tokenizer.size > 0) {
        char c = *tokenizer.current;
        switch (c) {
            case 'd': {
                tokenizer.current++;
                tokenizer.size--;
            } break;
            case 'i': {
                tokenizer.current++;
                tokenizer.size--;
                
                token.type = TOKEN_TYPE_NUMBER;
                token.num_value = get_number();

                return token;
            } break;
            case 'e': {
                tokenizer.current++;
                tokenizer.size--;
            } break;
            default: {
                if (c >= '0' && c <= '9') {
                    int string_length = calculate_string_length();
                    token.type = TOKEN_TYPE_STRING;
                    token.string_value = new_string(tokenizer.current, string_length);
                    
                    tokenizer.current += string_length;
                    tokenizer.size -= string_length;

                    return token;
                } else {
                    fprintf(stderr, "ERROR: char '%c' is not recognized\n", c);
                    exit(1);
                }
            }
        }
    }

    return token;
}

static void check_token_type(Token token, TokenType expected)
{
    if (token.type != expected) {
        fprintf(stderr, "ERROR: Token type error, expected '%s' but got '%s'. ", 
            get_token_type_name(expected), get_token_type_name(token.type));
        if (token.type == TOKEN_TYPE_STRING) {
            fprintf(stderr, "%.*s\n", (int)token.string_value.length, token.string_value.characters);
        } else if (token.type == TOKEN_TYPE_NUMBER) {
            fprintf(stderr, "%ld\n", token.num_value);
        }

        exit(1);
    }
}

static Torrent parse_torrent()
{
    Torrent torrent = {0};

    while (tokenizer.size > 0) {
        Token name_token = get_token();
        if (name_token.type == TOKEN_TYPE_COMPLETED) {
            break;
        }
        
        check_token_type(name_token, TOKEN_TYPE_STRING);

        if (strncmp(name_token.string_value.characters, "announce", strlen("announce")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_STRING);

            torrent.announce = value_token.string_value;
        } else if (strncmp(name_token.string_value.characters, "comment", strlen("comment")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_STRING);

            torrent.comment = value_token.string_value;
        } else if (strncmp(name_token.string_value.characters, "created by", strlen("created by")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_STRING);

            torrent.created_by = value_token.string_value;
        } else if (strncmp(name_token.string_value.characters, "creation date", strlen("creation date")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_NUMBER);

            torrent.creation_date = value_token.num_value;
        } else if (strncmp(name_token.string_value.characters, "info", strlen("info")) == 0) {
            torrent.info = (Info){0};

            // TODO: maybe if I parse the bencoded the entire file beforehand this would be easier. To do later.
            SHA1(tokenizer.current, tokenizer.size - 1 /* the last 'e' of the main dictionary*/, torrent.info_hash);
            // torrent.info_pointer = tokenizer.current - 4;
        } else if (strncmp(name_token.string_value.characters, "length", strlen("length")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_NUMBER);

            torrent.info.length = value_token.num_value;
        } else if (strncmp(name_token.string_value.characters, "name", strlen("name")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_STRING);

            torrent.info.name = value_token.string_value;
        } else if (strncmp(name_token.string_value.characters, "piece length", strlen("piece length")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_NUMBER);

            torrent.info.piece_length = value_token.num_value;
        }
        else if (strncmp(name_token.string_value.characters, "pieces", strlen("pieces")) == 0) {
            Token value_token = get_token();
            check_token_type(value_token, TOKEN_TYPE_STRING);
            
            torrent.info.pieces = value_token.string_value;
        }
    }

    return torrent;
}

static char *get_hash_as_string(u8 *hash, int hash_size, char *buffer, int buffer_size)
{
    assert(buffer_size == (hash_size*2));

    for (int i = 0; i < hash_size; ++i) {
        u8 byte = hash[i];
        int buffer_index = (i*2);
        sprintf(buffer + buffer_index, "%02X", byte);
    }
    
    return buffer;
}


int main(int argc, char **argv)
{
    char *filename = "test_data/kubuntu-24.04.2-desktop-amd64.iso.torrent";
    FILE *file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        int size = ftell(file);
        fseek(file, 0, SEEK_SET);

        u8 *content = (u8 *)malloc(size);
        fread(content, size, 1, file);
        fclose(file);

        tokenizer.start = content;
        tokenizer.current = content;
        tokenizer.size = size;

        Torrent torrent = parse_torrent();

        if (torrent.info.pieces.length % 20 != 0) {
            fprintf(stderr, "ERROR: Malformed pieces, should be multiple of 20\n");
            exit(1);
        }

        int i = 0;
        int piece_count = 0;
        while (i < torrent.info.pieces.length) {
            while (++i % 20 != 0)
                ;

            piece_count++;

        }
        
        printf("Pieces count = %d\n", piece_count);

        size_t info_size = sizeof(torrent.info.length) + torrent.info.name.length + sizeof(torrent.info.piece_length) + torrent.info.pieces.length;
        printf("Info size = %ld\n", info_size);

        // char hash[SHA_DIGEST_LENGTH];
        // char *result = SHA1(torrent.info_pointer, info_size, hash);
        // printf("hash = %s\n", result);
        char hash_buffer[SHA_DIGEST_LENGTH * 2];
        get_hash_as_string(torrent.info_hash, sizeof(torrent.info_hash), hash_buffer, sizeof(hash_buffer));
        printf("hash = %s\n", hash_buffer);


        if (torrent.info.length != 0) {
            // Single file
            // TODO: create entire file upfront. Then, as the pieces are downloaded, put it in the right spot.
        }
    }

    //
    // SHA-1
    //

    // printf("%d\n", SHA_DIGEST_LENGTH);

    // const size_t n = 13;
    // char *message = "Hello, World!";
    // char hash[SHA_DIGEST_LENGTH];
    // char *result = SHA1(message, n, hash);

    // printf("%s\n", hash);
    // printf("%s\n", result);
    
    return 0;
}
