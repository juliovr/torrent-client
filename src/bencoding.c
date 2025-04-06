#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

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

#define MAX_URL_LENGTH 2048

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

static void bytes_to_string_escaped(u8 *hash, int hash_size, char *dest)
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
    u64 length;
    u64 piece_length;
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
        torrent->length = ((BencodeNumber *)get_by_key(info, "length"))->value;
        torrent->piece_length = ((BencodeNumber *)get_by_key(info, "piece length"))->value;

        // Setting peer_id
        // char peer_id_bytes[SHA_DIGEST_LENGTH];
        if (RAND_bytes(torrent->peer_id, SHA_DIGEST_LENGTH) != 1) {
            fprintf(stderr, "ERROR: creating peer id.\n");
            exit(1);
        }

        bytes_to_string_escaped(torrent->peer_id, sizeof(torrent->peer_id), torrent->peer_id_string);


        // Setting info_hash
        SHA1(info->bencode.bencode_chars, info->bencode.bencode_size, torrent->info_hash);
        bytes_to_string_escaped(torrent->info_hash, sizeof(torrent->info_hash), torrent->info_hash_string);

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

    return result;
}

typedef struct TCPClient {
    CURL *curl;
    char *url;
    bool connected;
    long sockfd;
    fd_set ready_set;
} TCPClient;

TCPClient new_tcp_client(char *url)
{
    CURL *curl = curl_easy_init();
    
    TCPClient client = {
        .curl = curl,
        .url = url,
        .connected = false,
    };

    return client;
}

void tcp_client_connect(TCPClient *client)
{
    FD_ZERO(&client->ready_set);

    curl_easy_setopt(client->curl, CURLOPT_URL, client->url);
    /* Do not do the transfer - only connect to host */
    curl_easy_setopt(client->curl, CURLOPT_CONNECT_ONLY, 1L);

    CURLcode res;
   
    printf("Connecting to: %s\n", client->url);
    res = curl_easy_perform(client->curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: curl response code = %d\n", res);
        return;
    }

    /* Extract the socket from the curl handle - we need it for waiting. */
    long sockfd;
    res = curl_easy_getinfo(client->curl, CURLINFO_ACTIVESOCKET, &sockfd);
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: getting sockfd\n");
        return;
    }

    printf("sockfd = %ld\n", sockfd);

    client->connected = true;
    client->sockfd = sockfd;
}

bool tcp_client_is_valid(TCPClient *client)
{
    return client && client->curl;
}

void tcp_client_cleanup(TCPClient *client)
{
    if (tcp_client_is_valid(client)) {
        curl_easy_cleanup(client->curl);
    }
}

/*
 * The handshake is a required message and must be the first message transmitted by the client. It is (49+len(pstr)) bytes long.
 * handshake: <pstrlen><pstr><reserved><info_hash><peer_id> 
 */
typedef struct HandshakeData {
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

void make_handshake(TCPClient *client, HandshakeData *handshake_data)
{
    printf("Making handshake...\n");
    
    FD_ZERO(&client->ready_set);

    CURL *curl = client->curl;
    if (curl && client->connected) {
        CURLcode res;

        /* Send data */
        size_t sent;
        u8 handshake_serialized[128]; // TODO: make this dynamic
        memset(handshake_serialized, 0, sizeof(handshake_serialized));
        int handshake_serialized_size = handshake_data_serialize(handshake_serialized, handshake_data);
        res = curl_easy_send(curl, handshake_serialized, handshake_serialized_size, &sent);
        if (res != CURLE_OK) {
            fprintf(stderr, "ERROR: sending data making handshake\n");
            return;
        }

        FD_SET(client->sockfd, &client->ready_set);
        while (1) {
            select(client->sockfd + 1, &client->ready_set, NULL, NULL, NULL); // TODO: add timeout to avoid infinite loop
            if (FD_ISSET(client->sockfd, &client->ready_set)) {
                /* Receive response */
                char buf[512];
                size_t nread;
                res = curl_easy_recv(curl, buf, sizeof(buf), &nread);
                if (res != CURLE_OK) {
                    fprintf(stderr, "ERROR: getting handshake response\n");
                    return;
                }

                printf("Data received = %ld\n", nread);
                
                HandshakeData handshake_response;
                if (handshake_data_deserialize(&handshake_response, buf, nread)) {
                    fprintf(stderr, "ERROR: parsing response\n");
                    return;
                }

                if (validate_handshake(handshake_data, &handshake_response)) {
                    printf("Handshake OK\n");
                } else {
                    fprintf(stderr, "ERROR: handshake validation failed\n");
                }

                handshake_data_cleanup(&handshake_response);
                break;
            }
        }
        FD_CLR(client->sockfd, &client->ready_set);

        printf("Handshake completed\n");
    }
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
} Message;

void parse_message(char *buf, int size)
{
    u32 length = *((u32 *)buf);
    u8 message_id = buf[4];
    printf("length = %d\n", length);
    printf("message_id = %d\n", message_id);
    switch (message_id) {
        case MESSAGE_ID_CHOKE: printf("MESSAGE_ID_CHOKE: length = %d\n", length); break;
        case MESSAGE_ID_UNCHOKE: printf("MESSAGE_ID_UNCHOKE: length = %d\n", length); break;
        case MESSAGE_ID_INTERESTED: printf("MESSAGE_ID_INTERESTED: length = %d\n", length); break;
        case MESSAGE_ID_NOT_INTERESTED: printf("MESSAGE_ID_NOT_INTERESTED: length = %d\n", length); break;
        case MESSAGE_ID_HAVE: printf("MESSAGE_ID_HAVE: length = %d\n", length); break;
        case MESSAGE_ID_BITFIELD: printf("MESSAGE_ID_BITFIELD: length = %d\n", length); break;
        case MESSAGE_ID_REQUEST: printf("MESSAGE_ID_REQUEST: length = %d\n", length); break;
        default: {
            if (length == 0) {
                printf("MESSAGE_ID_KEEP_ALIVE\n");
                break;
            } else {
                fprintf(stderr, "ERROR: Unknown message\n");
            }
        }
    }
}

void send_unchoke(TCPClient *client)
{
    
}


int main(int argc, char **argv)
{
    // char *filename = "test_data/kubuntu-24.04.2-desktop-amd64.iso.torrent";
    char *filename = "test_data/debian-12.10.0-amd64-netinst.iso.torrent";
    Torrent torrent;
    if (parse_torrent(filename, &torrent)) {
        fprintf(stderr, "ERROR: parsing torrent\n");
        exit(1);
    }

    printf("Piece length = %ld\n", torrent.piece_length);

    PeersList peers_list = get_peers(&torrent);
    printf("n_peers = %d\n", peers_list.n);
    for (int i = 0; i < peers_list.n; ++i) {
        Peer peer = peers_list.peers[i];
        printf("ip = %.*s:%d\n", peer.ip.length, peer.ip.chars, peer.port);
    }

    HandshakeData handshake_data = create_handshake_data(torrent.info_hash, torrent.peer_id);
    Peer peer = peers_list.peers[0];

    char url[21] = "130.44.171.228:61310"; // TODO: use peer's data
    // snprintf(url, MAX_URL_LENGTH, "%.*s:%d", ip.length, ip.chars, port);
    
    TCPClient client = new_tcp_client(url);
    if (!tcp_client_is_valid(&client)) {
        fprintf(stderr, "ERROR: could not create client\n");
        exit(2);
    }

    tcp_client_connect(&client);

    make_handshake(&client, &handshake_data); // TODO: create a thread for each peer and do the connection

    send_unchoke(&client);
    
    tcp_client_cleanup(&client);

    return 0;
}
