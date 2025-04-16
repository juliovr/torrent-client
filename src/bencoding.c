#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <pthread.h>

#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include <curl/curl.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef float f32;
typedef double f64;


#define TO_BIG_ENDIAN(value)    ((((value) << 24) & 0xFF000000) | (((value) << 8) & 0xFF0000) | (((value) >> 8) & 0xFF00) | (((value) >> 24) & 0xFF))
#define FROM_BIG_ENDIAN(value)  TO_BIG_ENDIAN(value) /* It's the same as converting to big endian, i.e. flip the bytes */
#define PRINT_HEX(buf, size)            \
do {                                    \
    for (int i = 0; i < (size); ++i) {  \
        if (i % 8 == 0) {               \
            printf("\n");               \
        }                               \
        printf("%02X ", (u8)((buf)[i]));      \
    }                                   \
    printf("\n");                       \
} while (0)

#define KILOBYTE(n)         1024*(n)
#define MAX_URL_LENGTH      2048
#define MAX_REQUEST_SIZE    KILOBYTE(16)
#define MIN(a, b)           (((a) < (b)) ? (a) : (b))
#define MAX(a, b)           (((a) > (b)) ? (a) : (b))
#define TIMEOUT_MS          (10000L)

#ifdef _DEBUG_PRINT
    #ifdef _LINUX
        #define DEBUG_PRINT(format, ...) printf(format, ##__VA_ARGS__)
    #else
        #define DEBUG_PRINT(format, ...) printf(format, __VA_ARGS__)
    #endif
#else
#define DEBUG_PRINT(...)
#endif


typedef int bool;
#define true 1
#define false 0


typedef struct Tokenizer {
    u8 *start;
    u8 *current;
    size_t size;
} Tokenizer;

Tokenizer create_tokenizer(u8 *data, size_t size)
{
    return (Tokenizer) {
        .start = data,
        .current = data,
        .size = size,
    };
}

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

static string create_string(char *chars, int length)
{
    return (string) {
        .chars = chars,
        .length = length,
    };
}

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

Bencode *decode(Tokenizer *tokenizer);


static bool match(Tokenizer *tokenizer, char expected)
{
    if (tokenizer->size == 0) return false;
    if (*tokenizer->current != expected) return false;

    advance(tokenizer);
    return true;
}

static Bencode *decode_dictionary(Tokenizer *tokenizer)
{
    BencodeDictionary *dictionary = (BencodeDictionary *)malloc(sizeof(BencodeDictionary));
    dictionary->bencode.type = TYPE_DICTIONARY;
    dictionary->n = 0;

    u8 *start = tokenizer->current;
    
    advance(tokenizer); // Skip 'd'
    
    while (tokenizer->size > 0 && *tokenizer->current != 'e') {
        Bencode *key = decode(tokenizer);
        if (key->type != TYPE_STRING) {
            fprintf(stderr, "ERROR: key must be string.\n");
            exit(1);
        }

        Bencode *value = decode(tokenizer);

        dictionary->keys[dictionary->n] = key;
        dictionary->values[dictionary->n] = value;

        dictionary->n++;
    }
    if (!match(tokenizer, 'e')) {
        fprintf(stderr, "ERROR: Miss 'e'\n");
        exit(1);
    }

    dictionary->bencode.bencode_chars = start;
    dictionary->bencode.bencode_size = tokenizer->current - start;

    return (Bencode *)dictionary;
}

static Bencode *decode_list(Tokenizer *tokenizer)
{
    BencodeList *list = (BencodeList *)malloc(sizeof(BencodeList));
    list->bencode.type = TYPE_LIST;
    list->n = 0;

    u8 *start = tokenizer->current;
    
    advance(tokenizer); // Skip 'l'

    while (tokenizer->size > 0 && *tokenizer->current != 'e') {
        Bencode *value = decode(tokenizer);

        list->values[list->n] = value;

        list->n++;
    }
    if (!match(tokenizer, 'e')) {
        fprintf(stderr, "ERROR: Miss 'e'\n");
        exit(1);
    }

    list->bencode.bencode_chars = start;
    list->bencode.bencode_size = tokenizer->current - start;

    return (Bencode *)list;
}

static Bencode *decode_number(Tokenizer *tokenizer)
{
    BencodeNumber *number = (BencodeNumber *)malloc(sizeof(BencodeNumber));
    number->bencode.type = TYPE_NUMBER;

    u8 *start = tokenizer->current;

    advance(tokenizer); // Skip 'i'

    u64 num = strtoull(tokenizer->current, NULL, 0);
    
    while (tokenizer->size > 0 && *tokenizer->current != 'e') {
        advance(tokenizer);
    }
    if (!match(tokenizer, 'e')) {
        fprintf(stderr, "ERROR: Miss 'e'\n");
        exit(1);
    }

    number->value = num;

    number->bencode.bencode_chars = start;
    number->bencode.bencode_size = tokenizer->current - start;

    return (Bencode *)number;
}

static Bencode *decode_string(Tokenizer *tokenizer)
{
    BencodeString *string = (BencodeString *)malloc(sizeof(BencodeString));
    string->bencode.type = TYPE_STRING;

    int string_length = atoi(tokenizer->current);

    u8 *start = tokenizer->current;

    while (tokenizer->size > 0 && *tokenizer->current != ':') {
        advance(tokenizer);
    }

    if (!match(tokenizer, ':')) {
        fprintf(stderr, "ERROR: Miss ':'\n");
        exit(1);
    }

    string->str.chars = tokenizer->current;
    string->str.length = string_length;

    advance_by(tokenizer, string_length);

    string->bencode.bencode_chars = start;
    string->bencode.bencode_size = tokenizer->current - start;

    return (Bencode *)string;
}

Bencode *decode(Tokenizer *tokenizer)
{
    Bencode data = {0};

    char c = *tokenizer->current;
    switch (c) {
        case 'd': return decode_dictionary(tokenizer);
        case 'l': return decode_list(tokenizer);
        case 'i': return decode_number(tokenizer);
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
            return decode_string(tokenizer);
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


// If every byte has to be escaped, would be %nn, where nn is the value of the hex byte. 
// So, 1 byte, e.g. 0xAA, would the %AA (as string), which is 3 bytes.
#define MAX_LENGTH_BYTES_ESCAPED(size) (size*3)

static bool byte_should_be_escaped(u8 c)
{
    if (c >= '0' && c <= '9') return false;
    if (c >= 'a' && c <= 'z') return false;
    if (c >= 'A' && c <= 'Z') return false;
    switch (c) {
        case '.':
        case '-':
        case '_':
        case '~':
            return false;
        default: return true;
    }
}

static void bytes_to_string_escaped(char *dest, u8 *hash, int hash_size)
{
    int dest_index = 0;
    for (int i = 0; i < hash_size; ++i) {
        u8 byte = hash[i];
        if (byte_should_be_escaped(byte)) {
            sprintf(dest + dest_index, "%%%02X", byte);
            dest_index += 3;
        } else {
            sprintf(dest + dest_index, "%c", byte);
            dest_index++;
        }
    }
    dest[dest_index] = 0;
}

#define HASH_BUFFER_SIZE (SHA_DIGEST_LENGTH * 2)

typedef struct Torrent {
    string announce;
    int port;
    u8 peer_id[SHA_DIGEST_LENGTH];
    char peer_id_string[MAX_LENGTH_BYTES_ESCAPED(SHA_DIGEST_LENGTH)];
    u8 info_hash[SHA_DIGEST_LENGTH];
    char info_hash_string[MAX_LENGTH_BYTES_ESCAPED(SHA_DIGEST_LENGTH)];
    string filename;
    u64 length;
    u64 piece_length;
    int piece_count;
    u8 *piece_hashes;
} Torrent;


int parse_torrent(char *filename, Torrent *torrent)
{
    int code = 1;

    FILE *file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        int size = ftell(file);
        fseek(file, 0, SEEK_SET);

        u8 *content = (u8 *)malloc(size);
        fread(content, size, 1, file);
        fclose(file);


        Tokenizer tokenizer = create_tokenizer(content, size);

        Bencode *bencode = decode(&tokenizer);
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

        torrent->announce = ((BencodeString *)get_by_key(dictionary, "announce"))->str;
        torrent->port = 6881;
        torrent->filename = ((BencodeString *)get_by_key(info, "name"))->str;
        torrent->length = ((BencodeNumber *)get_by_key(info, "length"))->value;
        torrent->piece_length = ((BencodeNumber *)get_by_key(info, "piece length"))->value;

        Bencode *piece_hashes = get_by_key(info, "pieces");

        torrent->piece_count = ceil((f32)torrent->length / (f32)torrent->piece_length);
        torrent->piece_hashes = (u8 *)malloc(torrent->piece_count * SHA_DIGEST_LENGTH);

        memcpy(torrent->piece_hashes, ((BencodeString *)piece_hashes)->str.chars, piece_hashes->bencode_size);

        // Setting peer_id
        if (RAND_bytes(torrent->peer_id, SHA_DIGEST_LENGTH) != 1) {
            fprintf(stderr, "ERROR: creating peer id.\n");
            exit(1);
        }

        bytes_to_string_escaped(torrent->peer_id_string, torrent->peer_id, sizeof(torrent->peer_id));


        // Setting info_hash
        SHA1(info->bencode.bencode_chars, info->bencode.bencode_size, torrent->info_hash);
        bytes_to_string_escaped(torrent->info_hash_string, torrent->info_hash, sizeof(torrent->info_hash));


        code = 0;
    }

    return code;
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

typedef struct Response {
    char *body;
    size_t size;
} Response;

size_t response_callback(char *data, size_t size, size_t nmemb, void *dest)
{
    size_t real_size = size * nmemb;
    Response *response = (Response *)dest;

    response->body = (char *)malloc(real_size + 1);
    if (!response->body) {
        return 0; /* Out of memory */
    }

    memcpy(response->body, data, real_size);
    response->size = real_size;
    response->body[response->size] = 0;

    return real_size;
}

typedef struct Peer {
    string peer_id;
    string ip;
    int port;
} Peer;

typedef struct PeersList {
    Peer peers[128];
    int n;
} PeersList;

PeersList get_peers(Torrent *torrent)
{
    char *url = (char *)malloc(MAX_URL_LENGTH);
    snprintf(url, MAX_URL_LENGTH, "%.*s?info_hash=%.*s&peer_id=%.*s&port=%d&uploaded=0&downloaded=0&left=%ld",
        torrent->announce.length, torrent->announce.chars, 
        (int)strlen(torrent->info_hash_string), torrent->info_hash_string, 
        (int)sizeof(torrent->peer_id_string), torrent->peer_id_string,
        6881, torrent->length);

    printf("Making GET request to: %s\n", url);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    PeersList result = {0};

    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

        /*
         * If you want to connect to a site who is not using a certificate that is
         * signed by one of the certs in the CA bundle you have, you can skip the
         * verification of the server's certificate. This makes the connection
         * A LOT LESS SECURE.
         *
         * If you have a CA cert for the server stored someplace else than in the
         * default bundle, then the CURLOPT_CAPATH option might come handy for
         * you.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        /*
         * If the site you are connecting to uses a different host name that what
         * they have mentioned in their server certificate's commonName (or
         * subjectAltName) fields, libcurl refuses to connect. You can skip this
         * check, but it makes the connection insecure.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);


        Response response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);


        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        
        // printf("Response size = %ld\n", response.size);
        // printf("Response body = %s\n", response.body);


        Tokenizer tokenizer = create_tokenizer(response.body, response.size);
        
        Bencode *bencode_response = decode(&tokenizer);
        BencodeString *failure_reason = (BencodeString *)get_by_key((BencodeDictionary *)bencode_response, "failure reason");
        if (failure_reason != NULL) {
            fprintf(stderr, "ERROR: %.*s\n", failure_reason->str.length, failure_reason->str.chars);
            exit(1);
        }

        // Parse peers
        BencodeList *peers_list = (BencodeList *)get_by_key((BencodeDictionary *)bencode_response, "peers");
        if (peers_list) {
            for (int i = 0; i < peers_list->n; ++i) {
                BencodeDictionary *peer_entry = (BencodeDictionary *)peers_list->values[i];
                if (peer_entry) {
                    BencodeString *bencode_peer_id = ((BencodeString *)get_by_key(peer_entry, "peer_id"));
                    Peer peer = {
                        .peer_id = (bencode_peer_id == NULL) ? create_string("", 0) : bencode_peer_id->str,
                        .ip = ((BencodeString *)get_by_key(peer_entry, "ip"))->str,
                        .port = ((BencodeNumber *)get_by_key(peer_entry, "port"))->value,
                    };
                    result.peers[i] = peer;
                    result.n++;
                }
            }
        }

        // TODO: free(response.body); when I copy the body to the tokenizer
        

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    printf("Got peers\n");

    return result;
}

typedef struct TCPClient {
    CURL *curl;
    char *url;
    bool connected;
    int sockfd;
    fd_set ready_set;
    bool choked;
    u8 *bitfield;
    int bitfield_size;
} TCPClient;

TCPClient new_tcp_client(char *url)
{
    TCPClient client = {
        .url = url,
        .connected = false,
        .choked = true,
    };

    return client;
}

void tcp_client_connect(TCPClient *client)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    FD_ZERO(&client->ready_set);

    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_URL, client->url);
        /* Do not do the transfer - only connect to host */
        curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    
        CURLcode res;
       
        printf("Connecting to: %s\n", client->url);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "ERROR: %s\n", curl_easy_strerror(res));
            return;
        }
    
        /* Extract the socket from the curl handle - we need it for waiting. */
        curl_socket_t sockfd;
        res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
        if (res != CURLE_OK) {
            fprintf(stderr, "ERROR: %s\n", curl_easy_strerror(res));
            return;
        }
        printf("sockfd = %d\n", sockfd);

        client->curl = curl;
        client->connected = true;
        client->sockfd = sockfd;
    }
}

void tcp_client_cleanup(TCPClient *client)
{
    if (client->curl) {
        curl_easy_cleanup(client->curl);
    }

    curl_global_cleanup();
}

/*
 * The handshake is a required message and must be the first message transmitted by the client. It is (49+len(pstr)) bytes long.
 * handshake: <pstrlen><pstr><reserved><info_hash><peer_id> 
 */
typedef struct HandshakeData {
    int size;
    u8 pstrlen;
    char *pstr;
    u8 info_hash[SHA_DIGEST_LENGTH];
    u8 peer_id[SHA_DIGEST_LENGTH];
} HandshakeData;

HandshakeData create_handshake_data(u8 *info_hash, char *peer_id)
{
    HandshakeData result;
    result.pstr = "BitTorrent protocol";
    result.pstrlen = strlen(result.pstr);
    memcpy(result.info_hash, info_hash, sizeof(result.info_hash));
    memcpy(result.peer_id, peer_id, sizeof(result.peer_id));

    return result;
}

int handshake_data_serialize(u8 *handshake_serialized, HandshakeData *handshake_data)
{
    u8 *ptr = handshake_serialized;
    
    *ptr++ = handshake_data->pstrlen;
    
    memcpy(ptr, handshake_data->pstr, handshake_data->pstrlen);
    ptr += handshake_data->pstrlen;
    
    memset(ptr, 0, 8);
    ptr += 8;
    
    memcpy(ptr, handshake_data->info_hash, sizeof(handshake_data->info_hash));
    ptr += sizeof(handshake_data->info_hash);
    
    memcpy(ptr, handshake_data->peer_id, sizeof(handshake_data->peer_id));

    return 1 + handshake_data->pstrlen + 8 + sizeof(handshake_data->info_hash) + sizeof(handshake_data->peer_id);
}

int handshake_data_deserialize(HandshakeData *handshake, u8 *buf, int size)
{
    u8 *start = buf;

    if (size == 0) {
        fprintf(stderr, "ERROR: no data received\n");
        return 1;
    }

    int length = *buf++;
    if (length == 0) {
        fprintf(stderr, "ERROR: there is no length\n");
        return 1;
    }

    handshake->pstrlen = length;
    
    handshake->pstr = malloc(handshake->pstrlen);
    strncpy(handshake->pstr, buf, handshake->pstrlen);
    buf += handshake->pstrlen;
    
    buf += 8; // The 8 bytes padding.

    strncpy(handshake->info_hash, buf, sizeof(handshake->info_hash));
    buf += sizeof(handshake->info_hash);

    strncpy(handshake->peer_id, buf, sizeof(handshake->peer_id));
    buf += sizeof(handshake->peer_id);

    handshake->size = buf - start;

    return 0;
}

void handshake_data_cleanup(HandshakeData *handshake_data)
{
    if (!handshake_data) return;

    free(handshake_data->pstr);
}

bool validate_handshake(HandshakeData *a, HandshakeData *b)
{
    return memcmp(a->info_hash, b->info_hash, sizeof(a->info_hash)) == 0;
}


CURLcode send_data(TCPClient *client, u8 *data, int data_size)
{
    printf("Sending data...\n");

    long timeout_ms = TIMEOUT_MS;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (int)(timeout_ms % 1000) * 1000;

    CURLcode res;

    FD_ZERO(&client->ready_set);

    CURL *curl = client->curl;
    if (client->connected) {
        FD_SET(client->sockfd, &client->ready_set);
        while (1) {
            int select_result = select(client->sockfd + 1, NULL, &client->ready_set, NULL, &tv);
            if (select_result == 0) {
                fprintf(stderr, "ERROR: timeout\n");
                return 1;
            }
            if (select_result < 0) {
                fprintf(stderr, "ERROR: select()\n");
                return 2;
            }

            if (FD_ISSET(client->sockfd, &client->ready_set)) {
                size_t nsent_total = 0;
                do {
                    size_t nsent = 0;
                    res = curl_easy_send(curl, data + nsent_total, data_size - nsent_total, &nsent);
                    if (res == CURLE_OK) {
                        nsent_total += nsent;
                        printf("Sent = %ld bytes\n", nsent);
                    } else {
                        fprintf(stderr, "ERROR: %s\n", curl_easy_strerror(res));
                    }
                } while (nsent_total < data_size || res == CURLE_AGAIN);

                break;
            }
        }
    }

    FD_CLR(client->sockfd, &client->ready_set);

    return res;
}

CURLcode receive_data(TCPClient *client, char *buf, int buf_size, size_t *nread_total)
{
    printf("Receiving data...\n");

    long timeout_ms = TIMEOUT_MS;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (int)(timeout_ms % 1000) * 1000;


    CURLcode res;

    FD_ZERO(&client->ready_set);

    CURL *curl = client->curl;
    if (client->connected) {
        FD_SET(client->sockfd, &client->ready_set);
        while (1) {
            int select_result = select(client->sockfd + 1, &client->ready_set, NULL, NULL, &tv);
            if (select_result == 0) {
                fprintf(stderr, "ERROR: timeout\n");
                return 1;
            }
            if (select_result < 0) {
                fprintf(stderr, "ERROR: select()\n");
                return 2;
            }

            if (FD_ISSET(client->sockfd, &client->ready_set)) {
                res = curl_easy_recv(curl, buf, buf_size, nread_total);
                if (res != CURLE_OK) {
                    fprintf(stderr, "ERROR: %s\n", curl_easy_strerror(res));
                }

                printf("Received = %ld\n", *nread_total);

                break;
            }
        }
    }

    FD_CLR(client->sockfd, &client->ready_set);

    return res;
}

typedef enum MessageID {
    MESSAGE_ID_CHOKE            = 0,
    MESSAGE_ID_UNCHOKE          = 1,
    MESSAGE_ID_INTERESTED       = 2,
    MESSAGE_ID_NOT_INTERESTED   = 3,
    MESSAGE_ID_HAVE             = 4,
    MESSAGE_ID_BITFIELD         = 5,
    MESSAGE_ID_REQUEST          = 6,
    MESSAGE_ID_PIECE            = 7,
    MESSAGE_ID_CANCEL           = 8,
} MessageID;

typedef struct Message {
    MessageID id;
    u8 *payload;
    int payload_size;
} Message;

Message *buffer_to_message(u8 *buf, int data_size)
{
    if (data_size == 0) {
        return NULL;
    }

    int length = FROM_BIG_ENDIAN(*(int *)buf);
    buf += 4;

    int id = *buf++;
    
    int payload_size = length - 1; // Minus the 1-byte ID.
    if (payload_size < 0) {
        fprintf(stderr, "ERROR: payload_size negative\n");
        return NULL;
    }


    u8 *payload = (u8 *)malloc(payload_size);
    memcpy(payload, buf, payload_size);
    

    Message *message = (Message *)malloc(sizeof(Message));
    message->id = id;
    message->payload = payload;
    message->payload_size = payload_size;

    return message;
    
    // TODO: take this into consideration??
    // A bitfield of the wrong length is considered an error. 
    // Clients should drop the connection if they receive bitfields that are not of the correct size, 
    // or if the bitfield has any of the spare bits set.
}

Message *receive_message(TCPClient *client)
{
    CURLcode res;

    char buf[MAX_REQUEST_SIZE];
    size_t nread = 0;
    res = receive_data(client, buf, sizeof(buf), &nread);
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: could not receive request response\n");
        return NULL;
    }


    if (nread == 0) {
        fprintf(stderr, "ERROR: No data read\n");
        return NULL;
    }

    int length = FROM_BIG_ENDIAN(*(int *)buf);
    int id = buf[4];
    
    int payload_size = length - 1; // Minus the 1-byte ID.
    if (payload_size < 0) {
        fprintf(stderr, "ERROR: payload_size negative\n");
        return NULL;
    }


    u8 *payload = (u8 *)malloc(payload_size);
    int ncopied = 0;
    
    nread -= 5; // Length and ID.
    memcpy(payload, ((u8 *)buf) + 5, nread);
    ncopied += nread;

    while (ncopied < payload_size) {
        // Keep reading data if it's not full in the first call (given by length).

        nread = 0;
        res = receive_data(client, buf, sizeof(buf), &nread);
        if (res != CURLE_OK) {
            fprintf(stderr, "ERROR: could not receive request response\n");
            return NULL;
        }

        memcpy(payload + ncopied, buf, nread);
        ncopied += nread;
    }


    Message *message = (Message *)malloc(sizeof(Message));
    message->id = id;
    message->payload = payload;
    message->payload_size = payload_size;

    return message;
}

Message *make_handshake(TCPClient *client, HandshakeData *handshake_data)
{
    printf("Making handshake...\n");
    
    CURLcode res;

    u8 handshake_serialized[128]; // TODO: make this dynamic
    memset(handshake_serialized, 0, sizeof(handshake_serialized));
    int handshake_serialized_size = handshake_data_serialize(handshake_serialized, handshake_data);
    res = send_data(client, handshake_serialized, handshake_serialized_size);
    if (res != CURLE_OK) {
        return NULL;
    }

    char buf[512];
    size_t nread;
    res = receive_data(client, buf, sizeof(buf), &nread);
    if (res != CURLE_OK) {
        return NULL;
    }

    HandshakeData handshake_response;
    if (handshake_data_deserialize(&handshake_response, buf, nread)) {
        fprintf(stderr, "ERROR: parsing response\n");
        return NULL;
    }

    if (validate_handshake(handshake_data, &handshake_response)) {
        printf("Handshake OK\n");
    } else {
        fprintf(stderr, "ERROR: handshake validation failed\n");
        return NULL;
    }

    
    u8 *bitfield_data = (buf + handshake_response.size);
    Message *bitfield = buffer_to_message(bitfield_data, nread - handshake_response.size);
    if (bitfield->id != MESSAGE_ID_BITFIELD) {
        fprintf(stderr, "ERROR: id mismatch. Expected = %d, but got = %d\n", MESSAGE_ID_BITFIELD, bitfield->id);
        return NULL;
    }

    handshake_data_cleanup(&handshake_response);

    printf("Handshake completed\n");

    return bitfield;
}


void send_unchoke(TCPClient *client)
{
    printf("Sending unchoke message\n");

    int length = 1;
    
    u8 data[5];
    *((u32 *)data) = TO_BIG_ENDIAN(length);
    data[4] = MESSAGE_ID_UNCHOKE;
    
    CURLcode res = send_data(client, data, sizeof(data));
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: could not send unchoke\n");
    }
}

void send_interested(TCPClient *client)
{
    printf("Sending interested message\n");

    int length = 1;

    u8 data[5];
    *((u32 *)data) = TO_BIG_ENDIAN(length);
    data[4] = MESSAGE_ID_INTERESTED;

    CURLcode res = send_data(client, data, sizeof(data));
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: could not send interested\n");
    }
}

// typedef struct DownloadState {
//     TCPClient *client;
//     u32 piece_length;

// } DownloadState;

void send_have(TCPClient *client, int piece_index)
{
    printf("Sending have message\n");

    int length = 5;

    u8 data[9];
    *((u32 *)data) = TO_BIG_ENDIAN(length);
    data[4] = MESSAGE_ID_HAVE;
    *((u32 *)(data + 5)) = TO_BIG_ENDIAN(piece_index);

    CURLcode res = send_data(client, data, sizeof(data));
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: could not send have\n");
    }
}

int get_piece_length(Torrent *torrent, int piece_index)
{
    int begin = piece_index * torrent->piece_length;
    int end = begin + torrent->piece_length;;

    if (piece_index == torrent->piece_count - 1) {
        end = torrent->length;
    }

    return end - begin;
}

void download_piece(TCPClient *client, Torrent *torrent, FILE *file, int piece_index)
{
    // printf("================================================\n");
    // printf("Download piece %d\n", piece_index);

    CURLcode res;
    int length = 13;

    int piece_length = get_piece_length(torrent, piece_index);
    
    int remaining = piece_length;
    int downloaded = 0;

    u8 piece_buf[piece_length];
    
    while (remaining > 0) {
        // printf("--------------------\n");
        // printf("Remaining = %d\n", remaining);
        int byte_offset = downloaded;
        // int piece_request_size = MIN(MAX_REQUEST_SIZE, piece_length);
        int piece_request_size = MAX_REQUEST_SIZE;

        if (!client->choked) {
            u8 data[17];
            *((u32 *)data) = TO_BIG_ENDIAN(length);
            data[4] = MESSAGE_ID_REQUEST;
            *((u32 *)(data + 5)) = TO_BIG_ENDIAN(piece_index);
            *((u32 *)(data + 9)) = TO_BIG_ENDIAN(byte_offset);
            *((u32 *)(data + 13)) = TO_BIG_ENDIAN(piece_request_size);
        
            // printf("request payload:");
            // PRINT_HEX(data, sizeof(data));
        
            res = send_data(client, data, sizeof(data));
            if (res != CURLE_OK) {
                fprintf(stderr, "ERROR: could not send request\n");
                return;
            }
        }


        Message *message = receive_message(client); // Message NULL treated as keep-alive.
        if (message != NULL) {
            // printf("\nMessage received:\n");
            // printf("message_id = %d\n", message->id);
            // printf("payload_size = %d\n", message->payload_size);

            switch (message->id) {
                case MESSAGE_ID_CHOKE: {
                    client->choked = true;
                } break;
                case MESSAGE_ID_UNCHOKE: {
                    client->choked = false;
                } break;
                case MESSAGE_ID_PIECE: {
                    int index = FROM_BIG_ENDIAN(*((int *)(message->payload + 0)));
                    int begin = FROM_BIG_ENDIAN(*((int *)(message->payload + 4)));
                    u8 *block = message->payload + 8;
                    int block_size = message->payload_size - 8;
                    // printf("index = %d\n", index);
                    // printf("begin = %d\n", begin);
    
                    if (piece_index != index) {
                        fprintf(stderr, "ERROR: piece index does not match. Requested = %d, but got %d\n", piece_index, index);
                        return;
                    }
    
                    if (byte_offset != begin) {
                        fprintf(stderr, "ERROR: offset does not match. Requested = %d, but got %d\n", byte_offset, begin);
                        return;
                    }
    
                    remaining -= block_size;
                    downloaded += block_size;

                    memcpy(piece_buf + begin, block, block_size);
                } break;
            }
        }
    }

    u8 expected_hash[SHA_DIGEST_LENGTH];
    memcpy(expected_hash, torrent->piece_hashes + (piece_index * SHA_DIGEST_LENGTH), SHA_DIGEST_LENGTH);

    u8 hash_piece[SHA_DIGEST_LENGTH];
    SHA1(piece_buf, sizeof(piece_buf), hash_piece);

    if (memcmp(expected_hash, hash_piece, SHA_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "ERROR: piece hash does not match the expected hash from torrent\n");
        return;
    }

    send_have(client, piece_index);

    fseek(file, piece_index * torrent->piece_length, SEEK_SET);
    fwrite(piece_buf, 1, downloaded, file);
}


typedef struct QueueNode {
    int data;
    struct QueueNode *next;
} QueueNode;

typedef struct WorkQueue {
    QueueNode *first;
    QueueNode *last;
    int count;
    pthread_mutex_t mutex;
} WorkQueue;

void init_work_queue(WorkQueue *queue)
{
    queue->count = 0;
    
    if (pthread_mutex_init(&queue->mutex, NULL)) {
        fprintf(stderr, "ERROR: Could not initialize mutex\n");
        exit(1);
    }
}

void enqueue(WorkQueue *queue, int piece_index)
{
    if (pthread_mutex_lock(&queue->mutex)) {
        fprintf(stderr, "ERROR: Could not acquire the mutex\n");
        exit(1);
    }

    QueueNode *old_last = queue->last;
    queue->last = (QueueNode *)malloc(sizeof(QueueNode));
    queue->last->data = piece_index;
    
    if (queue->count == 0) {
        queue->first = queue->last;
    } else {
        old_last->next = queue->last;
    }
    
    queue->count++;
    
    if (pthread_mutex_unlock(&queue->mutex)) {
        fprintf(stderr, "ERROR: Could not release the mutex\n");
        exit(1);
    }
}

int dequeue(WorkQueue *queue, int *value) {
    if (pthread_mutex_lock(&queue->mutex)) {
        fprintf(stderr, "ERROR: Could not acquire the mutex\n");
        exit(1);
    }

    int result = 1;

    if (queue->count != 0) {
        *value = queue->first->data;
        QueueNode *old_first = queue->first;
        queue->first = queue->first->next;
        
        free(old_first);
    
        queue->count--;
        
        result = 0;
    }

    if (pthread_mutex_unlock(&queue->mutex)) {
        fprintf(stderr, "ERROR: Could not release the mutex\n");
        exit(1);
    }

    return result;
}

void cleanup_work_queue(WorkQueue *queue)
{
    // TODO: free in place instead of dequeueing the elements (overhead of reassigning pointers and mutex's locking).
    while (queue->count > 0) {
        int value;
        dequeue(queue, &value);
    }

    if (pthread_mutex_destroy(&queue->mutex)) {
        fprintf(stderr, "ERROR: Could not destroy mutex\n");
    }
}

typedef struct ThreadArgs {
    FILE *file;
    Torrent *torrent;
    PeersList *peers_list;
    WorkQueue *queue;
} ThreadArgs;

static void *
attempt_download_thread(void *arg)
{
    ThreadArgs *args = (ThreadArgs *)arg;
    FILE *file = args->file;
    Torrent *torrent = args->torrent;
    WorkQueue *queue = args->queue;
    PeersList *peers_list = args->peers->list;


    int piece_index;
    if (dequeue(queue, &piece_index)) {
        fprintf(stderr, "ERROR: Queue with no elements\n");
        return;
    }

    // TODO: I need a peer to connect to, but I cannot know if that peer has the piece I'm looking for until the connection is done.
    // Maybe just do the connection and if don't have the piece, close the connection and look for a new Peer.
    Peer *peer = find_peer_has_piece(peers_list, piece_index);

    HandshakeData handshake_data = create_handshake_data(torrent->info_hash, torrent->peer_id);
    

    // char url[21] = "89.115.213.213:56531"; // TODO: use peer's data
    char url[MAX_URL_LENGTH];
    snprintf(url, MAX_URL_LENGTH, "%.*s:%d", peer.ip.length, peer.ip.chars, peer.port);
    
    TCPClient client = new_tcp_client(url);
    tcp_client_connect(&client);

    Message *bitfield_message = make_handshake(&client, &handshake_data);
    if (bitfield_message != NULL) {
        client.bitfield = bitfield_message->payload;
        client.bitfield_size = bitfield_message->payload_size;
    
        send_unchoke(&client);
        send_interested(&client);
        
        download_piece(&client, torrent, file, piece_index);
    }

    tcp_client_cleanup(&client);
}

int main(int argc, char **argv)
{
    int ncores = (int)sysconf(_SC_NPROCESSORS_CONF);
    printf("Using ncores: %d\n", ncores);

    // char *torrent_filename = "test_data/kubuntu-24.04.2-desktop-amd64.iso.torrent";
    char *torrent_filename = "test_data/debian-12.10.0-amd64-netinst.iso.torrent";
    Torrent torrent;
    if (parse_torrent(torrent_filename, &torrent)) {
        fprintf(stderr, "ERROR: parsing torrent\n");
        exit(1);
    }

    char *filename = (char *)malloc(torrent.filename.length);
    strncpy(filename, torrent.filename.chars, torrent.filename.length);

    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "ERROR: Could not create file %s\n", filename);
        exit(1);
    }

    // printf("Piece length = %ld\n", torrent.piece_length);


    WorkQueue queue;
    init_work_queue(&queue);

    for (int piece_index = 0; piece_index < torrent.piece_count; ++piece_index) {
        enqueue(&queue, piece_index);
    }


    PeersList peers_list = get_peers(&torrent);
    // printf("n_peers = %d\n", peers_list.n);
    // for (int i = 0; i < peers_list.n; ++i) {
    //     Peer peer = peers_list.peers[i];
    //     printf("ip = %.*s:%d\n", peer.ip.length, peer.ip.chars, peer.port);
    // }
    

    pthread_t *threads = (pthread_t *)malloc(ncores * sizeof(pthread_t));

    for (int i = 0; i < ncores; ++i) {
        ThreadArgs args = {
            .file = file,
            .torrent = &torrent,
            .peers_list = &peers_list,
            .queue = &queue,
        };

        int res = pthread_create((thread + i), NULL, attempt_download_thread, args);
        if (res != 0) {
            fprintf(stderr, "ERROR: Could not create thread %d\n", i);
        }
    }

    for (int i = 0; i < ncores; ++i) {
        int res = pthread_join(threads[i], void **retval);
        if (res != 0) {
            fprintf(stderr, "ERROr: Could not join thread\n");
        }
    }

    fclose(file);

    return 0;
}
