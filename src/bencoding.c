#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

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

typedef struct string {
    char *chars;
    int length;
} string;

#define MAX_KEYS 128 /* TODO: maybe get rid of this and do it dynamically */

typedef enum BencodeType {
    TYPE_DICTIONARY,
    TYPE_LIST,
    TYPE_NUMBER,
    TYPE_STRING,
} BencodeType;

typedef struct Bencode {
    BencodeType type;
    u8 *bencode_chars;
    int bencode_size;
} Bencode;

typedef struct BencodeDictionary {
    Bencode bencode;
    int n;
    Bencode *keys[MAX_KEYS];
    Bencode *values[MAX_KEYS];
} BencodeDictionary;

typedef struct BencodeList {
    Bencode bencode;
    int n;
    Bencode *values[MAX_KEYS];
} BencodeList;

typedef struct BencodeNumber {
    Bencode bencode;
    u64 value;
} BencodeNumber;

typedef struct BencodeString {
    Bencode bencode;
    string str;
} BencodeString;


static Tokenizer tokenizer;

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
    dictionary->bencode.type = TYPE_DICTIONARY;
    dictionary->n = 0;

    u8 *start = tokenizer.current;
    
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

    dictionary->bencode.bencode_chars = start;
    dictionary->bencode.bencode_size = tokenizer.current - start;

    return (Bencode *)dictionary;
}

static Bencode *decode_list()
{
    BencodeList *list = (BencodeList *)malloc(sizeof(BencodeList));
    list->bencode.type = TYPE_LIST;
    list->n = 0;

    u8 *start = tokenizer.current;
    
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

    list->bencode.bencode_chars = start;
    list->bencode.bencode_size = tokenizer.current - start;

    return (Bencode *)list;
}

static Bencode *decode_number()
{
    BencodeNumber *number = (BencodeNumber *)malloc(sizeof(BencodeNumber));
    number->bencode.type = TYPE_NUMBER;

    u8 *start = tokenizer.current;

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

    number->bencode.bencode_chars = start;
    number->bencode.bencode_size = tokenizer.current - start;

    return (Bencode *)number;
}

static Bencode *decode_string()
{
    BencodeString *string = (BencodeString *)malloc(sizeof(BencodeString));
    string->bencode.type = TYPE_STRING;

    int string_length = atoi(tokenizer.current);

    u8 *start = tokenizer.current;

    while (tokenizer.size > 0 && *tokenizer.current != ':') {
        advance(&tokenizer);
    }

    if (!match(':')) {
        fprintf(stderr, "ERROR: Miss ':'\n");
        exit(1);
    }

    string->str.chars = tokenizer.current;
    string->str.length = string_length;

    advance_by(&tokenizer, string_length);

    string->bencode.bencode_chars = start;
    string->bencode.bencode_size = tokenizer.current - start;

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

Bencode *get_by_key(BencodeDictionary *dictionary, char *search_key)
{
    if (dictionary) {
        for (int i = 0; i < dictionary->n; ++i) {
            BencodeString *key = (BencodeString *)dictionary->keys[i];
            if (strncmp(key->str.chars, search_key, key->str.length) == 0) {
                return dictionary->values[i];
            }
        }
    }

    return NULL;
}



static void bytes_to_string(u8 *hash, int hash_size, char *dest, int dest_size)
{
    // assert(dest_size == (hash_size*2));

    for (int i = 0; i < hash_size; ++i) {
        u8 byte = hash[i];
        int dest_index = (i*2);
        sprintf(dest + dest_index, "%02X", byte);
    }
}

#define HASH_BUFFER_SIZE (SHA_DIGEST_LENGTH * 2)

typedef struct Torrent {
    string announce;
    int port;
    char peer_id[HASH_BUFFER_SIZE];
    char info_hash[HASH_BUFFER_SIZE];
    u64 length;
} Torrent;


void parse_torrent(char *filename)
{
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
        if (bencode->type != TYPE_DICTIONARY) {
            fprintf(stderr, "ERROR: data should be a dictionary bencoded.\n");
            exit(1);
        }
        
        BencodeDictionary *dictionary = (BencodeDictionary *)bencode;

        BencodeDictionary *info = (BencodeDictionary *)get_by_key(dictionary, "info");
        if (info == NULL) {
            fprintf(stderr, "ERROR: There is no info\n");
            exit(1);
        }
    
        BencodeString *pieces = (BencodeString *)get_by_key(info, "pieces");
        if (pieces == NULL) {
            fprintf(stderr, "ERROR: There are no pieces\n");
            exit(1);
        }

        if (pieces->str.length % 20 != 0) {
            fprintf(stderr, "ERROR: Malformed pieces, should be multiple of 20\n");
            exit(1);
        }

        Torrent torrent = {
            .announce = ((BencodeString *)get_by_key(dictionary, "announce"))->str,
            .port = 6881,
            .length = ((BencodeNumber *)get_by_key(info, "length"))->value,
        };


        char peer_id_bytes[SHA_DIGEST_LENGTH];
        if (RAND_bytes(peer_id_bytes, SHA_DIGEST_LENGTH) != 1) {
            fprintf(stderr, "ERROR: creating peer id.\n");
            exit(1);
        }

        bytes_to_string(peer_id_bytes, sizeof(peer_id_bytes), torrent.peer_id, sizeof(torrent.peer_id));

        printf("peer_id = %s\n", torrent.peer_id);

        // printf("bencode announce = %.*s\n", ((BencodeString *)get_by_key(dictionary, "announce"))->bencode.bencode_size, ((BencodeString *)get_by_key(dictionary, "announce"))->bencode.bencode_chars);
        // printf("bencode creation_date = %.*s\n", ((BencodeNumber *)get_by_key(dictionary, "creation date"))->bencode.bencode_size, ((BencodeNumber *)get_by_key(dictionary, "creation date"))->bencode.bencode_chars);
        // printf("bencode info size = %d\n", info->bencode.bencode_size);
        // printf("bencode info = %.*s\n", info->bencode.bencode_size, info->bencode.bencode_chars);

        u8 info_hash[SHA_DIGEST_LENGTH];
        SHA1(info->bencode.bencode_chars, info->bencode.bencode_size, info_hash);
        
        bytes_to_string(info_hash, sizeof(info_hash), torrent.info_hash, HASH_BUFFER_SIZE);
        printf("info_hash = %s\n", torrent.info_hash);


        // printf("info bytes = \n");
        // int byte_print = 3;
        // for (int i = 0; i < byte_print; ++i) {
        //     printf("   ");
        // }
        // for (int i = 0; i < info->bencode.bencode_size; ++i) {
        //     if (byte_print % 16 == 0) {
        //         printf("\n");
        //     }

        //     printf("%02X ", info->bencode.bencode_chars[i]);
        //     byte_print++;
        // }
        // printf("\n");
    }
}


/*
Usage:

Bencode *bencode = decode();
print_bencode(bencode);

printf("Searching for announce\n");
print_bencode(get_by_key((BencodeDictionary *)bencode, "announce"));

printf("Searching for name\n");
BencodeDictionary *info = (BencodeDictionary *)get_by_key((BencodeDictionary *)bencode, "info");
if (info == NULL) {
    printf("Not found\n");
} else {
    print_bencode(get_by_key(info, "name"));
}
*/
void print_bencode(Bencode *bencode)
{
    if (bencode == NULL) {
        return;
    }

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
            printf("%.*s\n", string->str.length, string->str.chars);
        } break;
        case TYPE_NUMBER: {
            BencodeNumber *number = (BencodeNumber *)bencode;
            printf("%ld\n", number->value);
        } break;
    }
}

int main(int argc, char **argv)
{
    // char *filename = "test_data/kubuntu-24.04.2-desktop-amd64.iso.torrent";
    char *filename = "test_data/debian-12.10.0-amd64-netinst.iso.torrent";
    parse_torrent(filename);
    

    return 0;
}
