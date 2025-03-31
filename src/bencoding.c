#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef int bool;
#define true 1
#define false 0


typedef struct Tokenizer {
    u8 *start;
    u8 *current;
    size_t size;
} Tokenizer;

static void advance(Tokenizer *tokenizer)
{
    tokenizer->current++;
    tokenizer->size--;
}

static void advance_by(Tokenizer *tokenizer, int n)
{
    tokenizer->current += n;
    tokenizer->size -= n;
}

Tokenizer tokenizer;

#define MAX_KEYS 128 /* TODO: maybe get rid of this and do it dynamically */

typedef enum BencodeType {
    TYPE_DICTIONARY,
    TYPE_LIST,
    TYPE_NUMBER,
    TYPE_STRING,
} BencodeType;

typedef struct Bencode {
    BencodeType type;
} Bencode;

typedef struct BencodeDictionary {
    BencodeType type;
    int n;
    Bencode *keys[MAX_KEYS];
    Bencode *values[MAX_KEYS];
} BencodeDictionary;

typedef struct BencodeList {
    BencodeType type;
    int n;
    Bencode *values[MAX_KEYS];
} BencodeList;

typedef struct BencodeNumber {
    BencodeType type;
    u64 value;
} BencodeNumber;

typedef struct BencodeString {
    BencodeType type;
    char *chars;
    int length;
} BencodeString;


Bencode *decode();


static bool match(char expected)
{
    if (tokenizer.size == 0) return false;
    if (*tokenizer.current != expected) return false;

    advance(&tokenizer);
    return true;
}

static Bencode *decode_dictionary()
{
    BencodeDictionary *dictionary = (BencodeDictionary *)malloc(sizeof(BencodeDictionary));
    dictionary->type = TYPE_DICTIONARY;
    dictionary->n = 0;

    advance(&tokenizer); // Skip 'd'
    
    while (tokenizer.size > 0 && *tokenizer.current != 'e') {
        Bencode *key = decode();
        if (key->type != TYPE_STRING) {
            fprintf(stderr, "ERROR: key must be string.\n");
            exit(1);
        }

        Bencode *value = decode();

        dictionary->keys[dictionary->n] = key;
        dictionary->values[dictionary->n] = value;

        dictionary->n++;
    }
    if (!match('e')) {
        fprintf(stderr, "ERROR: Miss 'e'\n");
        exit(1);
    }

    return (Bencode *)dictionary;
}

static Bencode *decode_list()
{
    BencodeList *list = (BencodeList *)malloc(sizeof(BencodeList));
    list->type = TYPE_LIST;
    list->n = 0;

    advance(&tokenizer); // Skip 'l'

    while (tokenizer.size > 0 && *tokenizer.current != 'e') {
        Bencode *value = decode();

        list->values[list->n] = value;

        list->n++;
    }
    if (!match('e')) {
        fprintf(stderr, "ERROR: Miss 'e'\n");
        exit(1);
    }

    return (Bencode *)list;
}

static Bencode *decode_number()
{
    BencodeNumber *number = (BencodeNumber *)malloc(sizeof(BencodeNumber));
    number->type = TYPE_NUMBER;

    advance(&tokenizer); // Skip 'i'

    u64 num = strtoull(tokenizer.current, NULL, 0);
    
    while (tokenizer.size > 0 && *tokenizer.current != 'e') {
        advance(&tokenizer);
    }
    if (!match('e')) {
        fprintf(stderr, "ERROR: Miss 'e'\n");
        exit(1);
    }

    number->value = num;

    return (Bencode *)number;
}

static Bencode *decode_string()
{
    BencodeString *string = (BencodeString *)malloc(sizeof(BencodeString));
    string->type = TYPE_STRING;

    int string_length = atoi(tokenizer.current);

    while (tokenizer.size > 0 && *tokenizer.current != ':') {
        advance(&tokenizer);
    }
    if (!match(':')) {
        fprintf(stderr, "ERROR: Miss ':'\n");
        exit(1);
    }

    string->chars = tokenizer.current;
    string->length = string_length;

    advance_by(&tokenizer, string_length);

    return (Bencode *)string;
}

Bencode *decode()
{
    Bencode data = {0};

    char c = *tokenizer.current;
    switch (c) {
        case 'd': return decode_dictionary();
        case 'l': return decode_list();
        case 'i': return decode_number();
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return decode_string();
        default:
            return NULL;
    }
}

void parse_torrent(char *filename)
{
    // TODO: read the file here
    // TODO: create the tokenizer
    Bencode *bencode = decode();
    if (bencode->type != TYPE_DICTIONARY) {
        fprintf(stderr, "ERROR: data should be a dictionary bencoded.\n");
        exit(1);
    }

    // TODO: process the file here...
}

Bencode *get_by_key(BencodeDictionary *dictionary, char *search_key)
{
    for (int i = 0; i < dictionary->n; ++i) {
        BencodeString *key = (BencodeString *)dictionary->keys[i];
        if (strncmp(key->chars, search_key, key->length) == 0) {
            return dictionary->values[i];
        }
    }

    return NULL;
}

void print_bencode(Bencode *bencode)
{
    switch (bencode->type) {
        case TYPE_DICTIONARY: {
            BencodeDictionary *dictionary = (BencodeDictionary *)bencode;
            printf("{\n");
            for (int i = 0; i < dictionary->n; ++i) {
                print_bencode(dictionary->keys[i]);
                print_bencode(dictionary->values[i]);
            }
            printf("}\n");
        } break;
        case TYPE_LIST: {
            BencodeList *list = (BencodeList *)bencode;
            printf("[\n");
            for (int i = 0; i < list->n; ++i) {
                print_bencode(list->values[i]);
            }
            printf("]\n");
        } break;
        case TYPE_STRING: {
            BencodeString *string = (BencodeString *)bencode;
            printf("%.*s\n", string->length, string->chars);
        } break;
        case TYPE_NUMBER: {
            BencodeNumber *number = (BencodeNumber *)bencode;
            printf("%ld\n", number->value);
        } break;
    }
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

        Bencode *bencode = decode();
        print_bencode(bencode);


        printf("Searching for announce\n");
        Bencode *value = get_by_key(bencode, "announce");
        print_bencode(value);

        // if (torrent.info.pieces.length % 20 != 0) {
        //     fprintf(stderr, "ERROR: Malformed pieces, should be multiple of 20\n");
        //     exit(1);
        // }
    }

    return 0;
}
