#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

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
    }
    tokenizer.current++;

    return string_length;
}

static u64 get_number()
{
    u64 num = strtoull(tokenizer.current, NULL, 0);
    
    while (*tokenizer.current != 'e') {
        tokenizer.current++;
    }
    tokenizer.current++;

    return num;
}

void print_bencoded()
{
    int ident = 0;
    while (tokenizer.size--) {
        char c = *tokenizer.current;
        switch (c) {
            case 'd': {
                printf("Dictionary:\n");
                ident += 4;
                tokenizer.current++;
            } break;
            case 'i': {
                tokenizer.current++;
                u64 num = get_number();
                print_ident(ident);
                printf("%ld\n", num);
            } break;
            case 'e': {
                ident -= 4;
                tokenizer.current++;
            } break;
            default: {
                if (c >= '0' && c <= '9') {
                    int string_length = calculate_string_length();
                    print_ident(ident);
                    printf("%.*s\n", string_length, tokenizer.current);
                    
                    tokenizer.current += string_length;
                } else {
                    fprintf(stderr, "ERROR: char '%c' is not recognized\n", c);
                    exit(1);
                }
            }
        }
    }
}

typedef enum TokenType TokenType;
enum TokenType {
    TOKEN_TYPE_NUMBER,
    TOKEN_TYPE_STRING,

    TOKEN_TYPE_INVALID,

    TOKEN_TYPE_COUNT,
};

static char *get_token_type_name(TokenType type)
{
    switch (type) {
        case TOKEN_TYPE_NUMBER: return "TOKEN_TYPE_NUMBER";
        case TOKEN_TYPE_STRING: return "TOKEN_TYPE_STRING";
        case TOKEN_TYPE_INVALID: return "TOKEN_TYPE_INVALID";
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
    token.type = TOKEN_TYPE_INVALID;

    while (tokenizer.size--) {
        char c = *tokenizer.current;
        switch (c) {
            case 'd': {
                tokenizer.current++;
            } break;
            case 'i': {
                tokenizer.current++;
                
                token.type = TOKEN_TYPE_NUMBER;
                token.num_value = get_number();

                return token;
            } break;
            case 'e': {
                tokenizer.current++;
            } break;
            default: {
                if (c >= '0' && c <= '9') {
                    int string_length = calculate_string_length();
                    token.type = TOKEN_TYPE_STRING;
                    token.string_value = new_string(tokenizer.current, string_length);
                    
                    tokenizer.current += string_length;

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

    while (tokenizer.size--) {
        Token name_token = get_token();
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
            break;
            // Token value_token = get_token();
            // check_token_type(value_token, TOKEN_TYPE_STRING);

            // torrent.info.pieces = value_token.string_value;
        }
    }

    return torrent;
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

        tokenizer.start = content;
        tokenizer.current = content;
        tokenizer.size = size;
        // print_bencoded();

        Torrent torrent = parse_torrent();

        fclose(file);
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
