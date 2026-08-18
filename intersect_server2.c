#define _GNU_SOURCE

#include "libote_wrap.h"
#include "gc_wrap.h"
#include "aux.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <sodium.h>
#include <pthread.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#define SPORT 8080
#define CPORT 8082
#define GCPORT 1212
const static char* target_addr = "127.0.0.1";

 
 /*send and receive code */
 /*   uint8_t *arr;
    uint64_t count;
    int rc = recv_uint8_array(new_socket, &arr, &count);
    
    fprintf(stderr, "recv_uint8_array returned: %d\n", rc);
    if (rc == 0) {
        printf("received %" PRIu64 " elements\n", count);
        for(uint64_t i = 0; i < count; i++)
            printf("%" PRIu8 "\n", arr[i]);
        free(arr);
    }
    else{
        fprintf(stderr, "recv failed: rc = %d errno = %s\n", rc, strerror(errno));
    }
    
    if(send_uint32_array(new_socket, clientdata, 3) != 0)
        perror("send failed");*/
#define MAX_EVENTS      512          /* epoll events per call                */
#define MAX_CONNECTIONS 65536        /* fd-indexed connection table size      */
#define RECV_BUF_SIZE   4096         /* per-read stack buffer                 */
#define BACKLOG         1024         /* listen() backlog                      */
#define SEND_BATCH_SIZE 256
#define MAX_ARRAY_ELEMENTS 64ULL * 1024ULL * 1024ULL
static const bool local = true;
static int          shutdown_requested = 0;
static time_t       shutdown_deadline  = 0;
static int          active_count       = 0;  // increment on accept, decrement on close
#define GRACEFUL_TIMEOUT_SECS 1
//static const uint64_t MAX_ARRAY_ELEMENTS = 1ULL << 32;
/* Batch size for the htonl/ntohl conversion loop in send/recv.
 * 256 elements = 1 KB on the stack, regardless of the total array size. */
 
static bool verbose, cout, light;
static uint32_t m, L, line, FF_size, expon, THRESHOLD; //n = number of records, m = number of attributes, L = bitlength per attribute, line = record bitlength
volatile int n = 0, nbytes;
double artificial_delay = 0., RTT = 0.05; //50ms delay to send data
bool benchmarking = false;
const int rsize = 3;
static int self_fd, s1_fd;
static int exchange_eventfd = -1;

//const static int extra_buf_space = 100000;
//static int remaining_buf_space = extra_buf_space;
static uint8_t *D;
static int D2_cols;
#define D2(r, c) D[(r) * D2_cols + (c)]

//bencmarking...
double univ_start = 0, univ_end = 0, univ_final;

typedef enum {
    INTERSECT_FULL = 0,
    INTERSECT_MINUS,
} intersect_version_t;

typedef enum {
    CONN_FREE = 0,
    CONN_ACTIVE,
    CONN_CLOSING,
} conn_state_t;

typedef enum {
    PARSE_READING_HEADER,   // waiting to accumulate 8 header bytes
    PARSE_READING_PAYLOAD,  // waiting to accumulate `count` payload bytes
} parse_state_t;

typedef struct write_chunk {
    uint8_t         *buf;
    size_t           len;
    size_t           off;       // how many bytes of this chunk already sent
    struct write_chunk *next;
} write_chunk_t;

typedef struct {
    parse_state_t state;

    // Header accumulation
    uint8_t  header_buf[8];
    size_t   header_got;    // how many header bytes received so far

    // Payload accumulation
    uint64_t count;         // decoded from header
    uint8_t *payload;       // malloc'd buffer
    size_t   payload_got;   // how many payload bytes received so far
} parser_t;

typedef struct {
    int fd;
    bool ret;
    conn_state_t conn_state;
    parse_state_t parse_state;

    parser_t parser;
    write_chunk_t *write_head;  // currently sending
    write_chunk_t *write_tail;  // append new chunks here
} connection_t;

typedef struct {
    int client_fd;
    uint8_t *arr;
    uint64_t count;
} query_thread_args;

typedef struct {
    int client_fd;
    uint8_t *response;
    uint64_t response_len;
} query_thread_result;

typedef struct result_node {
    query_thread_result   *result;
    struct result_node  *next;
} result_node_t;

typedef struct {
    result_node_t  *head;
    result_node_t  *tail;
} result_queue_t;

static result_queue_t  result_queue       = {NULL, NULL};
static pthread_mutex_t result_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static const intersect_version_t intersect_version = INTERSECT_FULL;

static connection_t conn_table[MAX_CONNECTIONS];
static int          epoll_fd  = -1;
static volatile int running   = 1;


static int send_8(int target_fd, uint8_t *arr, uint64_t count){
    if(send_uint8_array(target_fd, arr, count, SEND_BATCH_SIZE) != 0){
        fprintf(stderr, "send failed\n");
        return -1;
    }
    return 0;
}

static int send_32(int target_fd, uint32_t *arr, uint64_t count){
    if(send_uint32_array(target_fd, arr, count, SEND_BATCH_SIZE) != 0){
        fprintf(stderr, "send failed\n");
        return -1;
    }
    return 0;
}

static int receive_8(int target_fd, uint8_t **out_arr, uint64_t *out_count){
    uint8_t *arr;
    uint64_t count;
    int rc = recv_uint8_array(target_fd, &arr, &count, MAX_ARRAY_ELEMENTS);

    if(rc == -1){
        fprintf(stderr, "recv failed: syscall error: %s\n", strerror(errno));
        return -1;
    }
    else if(rc == -2){
        fprintf(stderr, "recv failed: server closed connection unexpectedly\n");
        return -1;
    }
    else if(rc < -2){
        fprintf(stderr, "recv failed: rc=%d\n", rc);
        return -1;
    }
    *out_arr = arr;
    *out_count = count;
    return 0;
}

static int receive_32(int target_fd, uint32_t **out_arr, uint64_t *out_count){
    uint32_t *arr;
    uint64_t count;
    int rc = recv_uint32_array(target_fd, &arr, &count, MAX_ARRAY_ELEMENTS);

    if(rc == -1){
        fprintf(stderr, "recv failed: syscall error: %s\n", strerror(errno));
        return -1;
    }
    else if(rc == -2){
        fprintf(stderr, "recv failed: server closed connection unexpectedly\n");
        return -1;
    }
    else if(rc < -2){
        fprintf(stderr, "recv failed: rc=%d\n", rc);
        return -1;
    }
    *out_arr = arr;
    *out_count = count;
    return 0;
}

static void enqueue_result(result_queue_t *q, query_thread_result *result){
    result_node_t *node = malloc(sizeof(result_node_t));
    node->result = result;
    node->next   = NULL;
    if (q->tail) {
        q->tail->next = node;
        q->tail       = node;
    } else {
        q->head = node;
        q->tail = node;
    }
}

static query_thread_result *dequeue_result(result_queue_t *q){
    if (!q->head){
        fprintf(stderr, "head not initialised\n");
        return NULL;
    }
    result_node_t *node = q->head;
    query_thread_result *result = node->result;
    q->head = node->next;
    if (!q->head)
        q->tail = NULL;
    free(node);
    return result;
}

/* Make a file descriptor non-blocking. */
static int set_nonblocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void on_signal(int sig){
    (void)sig;
    if (shutdown_requested) {
        // Second signal — give up and exit immediately
        running = 0;
        return;
    }
    shutdown_requested = 1;
    shutdown_deadline  = time(NULL) + GRACEFUL_TIMEOUT_SECS;
}
/* Register fd with epoll (edge-triggered, readable + writable). */
static int epoll_add(int fd, uint32_t events){
    struct epoll_event ev = {
        .events  = events,
        .data.fd = fd,
    };
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

/* Modify an existing epoll registration. */
static int epoll_mod(int fd, uint32_t events){
    struct epoll_event ev = {
        .events  = events,
        .data.fd = fd,
    };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

/* -------------------------------------------------------------------------
 * Connection lifecycle
 * ---------------------------------------------------------------------- */

static void connection_close(int fd){
    active_count--;
    if (fd < 0 || fd >= MAX_CONNECTIONS) return;

    connection_t *c = &conn_table[fd];
    if (c->conn_state == CONN_FREE) return;

    printf("Connection closed: fd=%d\n", fd);

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);

    /* Free any per-connection resources here. */
    memset(c, 0, sizeof(*c));
    c->conn_state = CONN_FREE;
    if(c->parser.payload != NULL) free(c->parser.payload);
    write_chunk_t *chunk = c->write_head;

    while (chunk) {
        write_chunk_t *next = chunk->next;
        free(chunk->buf);
        free(chunk);
        chunk = next;
    }
    c->write_head = NULL;
    c->write_tail = NULL;
}

static void servers_communicate(){
    artificial_delay += RTT;
}

static int s1_connect(){
    int status;
    struct sockaddr_in serv_addr;
    if ((s1_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SPORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, target_addr, &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    fprintf(stderr, "Attempting to connect...\n");
    if ((status = connect(s1_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    fprintf(stderr, "Connected to s1\n");
    return s1_fd;
}

int s1_hello(){
    uint32_t *recv_arr;
    uint64_t count;
    if(receive_32(s1_fd, &recv_arr, &count) == 0 && count == 8){
        n = recv_arr[0];
        m = recv_arr[1];
        L = recv_arr[2];
        verbose = recv_arr[3];
        cout = recv_arr[4];
        light = recv_arr[5];
        FF_size = recv_arr[6];
        THRESHOLD = recv_arr[7];
    }
    else{
        fprintf(stderr, "s1_hello failed\n");
        return -1;
    }
    if(verbose)
        printf("Finished server_hello\n");
    free(recv_arr);
    return 0;
}


static int create_listen_socket(uint16_t port){
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd == -1) { perror("socket"); return -1; }

    /* Allow quick restart after crash (avoids TIME_WAIT bind errors). */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(port),
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, BACKLOG) == -1) {
        perror("listen"); close(fd); return -1;
    }

    return fd;
}

static int print_records(){
    if(n > 100) return 1;
    uint8_t (*D1)[nbytes] = NULL;
    uint8_t *recv_arr;
    uint64_t count, exp_count = nbytes * line;

    uint8_t D2_send[line][nbytes];
    for(int i = 0; i < line; i++)
        memcpy(D2_send[i], &D2(i, 0), nbytes);

    if(send_8(s1_fd, (uint8_t*)D2_send, exp_count) != 0)
        return -1;

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == exp_count)
        D1 = (void *)recv_arr;
    else{
        fprintf(stderr, "receive D1 from s1 failed\n");
        return -1;
    }

    bool d;
    for(int i = 0; i < n; i++){
        for(int j = 0; j < line; j++){
            d = (D2(j, i/8) >> i%8 & 1)  ^ (D1[j][i/8] >> i%8 & 1);
            if(j == 0 && j == line - 1)
                printf("(%d)\n", d);
            else if(j == 0 && j % L == L - 1)
                printf("(%d|", d);
            else if(j == 0)
                printf("(%d", d);
            else if(j == line - 1)
                printf("%d)\n", d);
            else if(j % L == L - 1)
                printf("%d|", d);
            else printf("%d", d);
        }
    }
    printf("\n");
    free(D1);
    return 0;
}

//D_i is each server's boolean share of the record data, I_i is the computed intersection shares
static int intersectminus(int n_fixed, int l, int L, int no_multis_bytes, uint8_t (*alt_D)[tobytes(n_fixed)], uint8_t (*T2)[no_multis_bytes], uint8_t **Z2, int *intersect_indices, bool *t){
    int nbytes_fixed = tobytes(n_fixed);
    int lhalf = l - (l / 2);
    int initsize = lhalf * nbytes_fixed * sizeof(uint8_t);
    int de_size = (l / 2) * nbytes_fixed * sizeof(uint8_t);
    uint8_t (*I2)[nbytes_fixed] = malloc(initsize);
    if(!I2){
        fprintf(stderr, "could not allocate I1\n");
        return -1;
    }
    
    uint8_t (*d2)[nbytes_fixed] = malloc(de_size), (*e2)[nbytes_fixed] = malloc(de_size);
    uint8_t (*d1)[nbytes_fixed] = NULL, (*e1)[nbytes_fixed] = NULL; // should get malloc'ed by recv()
    uint8_t (*d)[nbytes_fixed] = NULL, (*e)[nbytes_fixed] = NULL; // will reuse from d2 and e2
    if(!d2 || !e2){
        fprintf(stderr, "could not allocate d or e arrays\n");
        return -1;
    }
    
    int index1, index2;
    int index_len = l / L;
    int no_pairs = l / 2; //e.g. if we have 7 indices, we have 3 pairs and 1 leftover
    bool uneven = no_pairs * 2 != l;
    l -= no_pairs;

    int index = 0, subindex = 0, j = 0;
    for(int pair = 0; pair < no_pairs; pair++){
        for(int i = 0; i < nbytes_fixed; i++){
            index1 = intersect_indices[index] * L + subindex;
            index2 = subindex + 1 == L? intersect_indices[index + 1] * L: index1 + 1;
            if(alt_D){
                //printf("using altD\n");
                d2[pair][i] = alt_D[index1][i] ^ (255 * t[index * L + subindex]) ^ T2[0][j] ^ 255;
                e2[pair][i] = alt_D[index2][i] ^ (255 * t[index * L + subindex + 1]) ^ T2[1][j++] ^ 255;
            }
            else{
                d2[pair][i] = D2(index1, i) ^ (255 * t[index * L + subindex]) ^ T2[0][j] ^ 255;
                e2[pair][i] = D2(index2, i) ^ (255 * t[index * L + subindex + 1]) ^ T2[1][j++] ^ 255;
            }
        }
        subindex++;
        if(subindex == L){
            subindex -= L;
            index++;
        }
        subindex++;
        if(subindex == L){
            subindex -= L;
            index++;
        }
    }
    uint8_t *recv_arr;
    uint64_t count;

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == de_size){
        d1 = (void *)recv_arr;
        d = d1;
    }
    else{
        fprintf(stderr, "receive d1 from s1 failed\n");
        return -1;
    }
    if(send_8(s1_fd, (uint8_t *)d2, de_size) != 0){
        fprintf(stderr, "send d2 to s1 failed\n");
        return -1;
    }

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == de_size){
        e1 = (void *)recv_arr;
        e = e1;
    }
    else{
        fprintf(stderr, "receive e1 from s1 failed\n");
        return -1;
    }

    if(send_8(s1_fd, (uint8_t *)e2, de_size) != 0){
        fprintf(stderr, "send e2 to s1 failed\n");
        return -1;
    }
    j = 0;
    for(int pair = 0; pair < no_pairs; pair++){
        for(int i = 0; i < nbytes_fixed; i++){
            //now we assume both servers have all parts to reconstruct d and e, and thus both calculate:
            d[pair][i] = d1[pair][i] ^ d2[pair][i];
            e[pair][i] = e1[pair][i] ^ e2[pair][i];
            //server 1 computes z1 as d*b1 + e*a1 + c1
            //server 2 computes z2 as d*e + d*b2 + e*a2 + c2
            I2[pair][i] = (d[pair][i] & e[pair][i]) ^ (d[pair][i] & T2[1][j]) ^ (e[pair][i] & T2[0][j]) ^ T2[2][j];
            j++;
        }
    }
    free(d1);
    free(e1);

    
    if(uneven){
        int leftoverindex = (intersect_indices[index_len - 1] + 1) * L - 1;
        for(int i = 0; i < nbytes_fixed; i++){
            if(alt_D)
                I2[no_pairs][i] = alt_D[leftoverindex][i] ^ (255 * t[index * L + subindex]) ^ 255;
            else I2[no_pairs][i] = D2(leftoverindex, i) ^ (255 * t[index * L + subindex]) ^ 255;
        }
    }
    
    int jcheckpoint, spacing;
    int no_rounds = (int)ceil(log2(l));
    for(int round = 0; round < no_rounds; round++){
        no_pairs = l / 2; //e.g. if we have 7 indices, we have 3 pairs and 1 leftover
        l -= no_pairs;
        spacing = (int)pow(2, round);
        jcheckpoint = j;
        for(int pair = 0; pair < no_pairs; pair++){
            index1 = 2*pair*spacing; //first index of the pair
            index2 = spacing*(2*pair + 1); //second index of the pair=
            for(int i = 0; i < nbytes_fixed; i++){
                d2[pair][i] = I2[index1][i] ^ T2[0][j];
                e2[pair][i] = I2[index2][i] ^ T2[1][j++];
            }
        }
        j = jcheckpoint;
        int sendsize = no_pairs * nbytes_fixed;
        if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == sendsize){
            d1 = (void *)recv_arr;
            d = d1;
        }
        else{
            fprintf(stderr, "receive d1 from s1 failed\n");
            return -1;
        }
        if(send_8(s1_fd, (uint8_t *)d2, sendsize) != 0){
            fprintf(stderr, "send d2 to s1 failed\n");
            return -1;
        }

        if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == sendsize){
            e1 = (void *)recv_arr;
            e = e1;
        }
        else{
            fprintf(stderr, "receive e1 from s1 failed\n");
            return -1;
        }

        if(send_8(s1_fd, (uint8_t *)e2, sendsize) != 0){
            fprintf(stderr, "send e2 to s1 failed\n");
            return -1;
        }

        //servers publish shares, i.e. server 1 sends D1 and E1, server 2 similarly
        for(int pair = 0; pair < no_pairs; pair++){
            index1 = 2*pair*spacing;
            for(int i = 0; i < nbytes_fixed; i++){
                //now both servers have all parts to reconstruct D and E, and thus both calculate:
                d[pair][i] = d1[pair][i] ^ d2[pair][i];
                e[pair][i] = e1[pair][i] ^ e2[pair][i];
                //server 1 computes z1 as d*b1 + e*a1 + c1
                //I2[index1][i] = (d[pair][i] & T2[1][j]) ^ (e[pair][i] & T2[0][j]) ^ T2[2][j];
                //server 2 computes z2 as d*e + d*b2 + e*a2 + c2
                I2[index1][i] = (d[pair][i] & e[pair][i]) ^ (d[pair][i] & T2[1][j]) ^ (e[pair][i] & T2[0][j]) ^ T2[2][j];
                j++;
            }
        }
        free(d1);
        free(e1);
    }

    *Z2 = realloc(I2, nbytes_fixed);
    if(!Z2){
        fprintf(stderr, "error reallocating Z2\n");
        return -1;
    }
    free(d2);
    free(e2);
    return 0;
}

int intersectfull(int n_fixed, int no_multis_bytes, uint8_t (*T2)[no_multis_bytes], uint8_t **Z2, bool *q, bool *t){
    int nbytes_fixed = tobytes(n_fixed);
    int l = L;  //l is now the length of each subvector
    int lhalf = l - (l / 2);
    int initsize = lhalf * m * nbytes_fixed * sizeof(uint8_t);
    uint8_t (*I2)[lhalf][nbytes_fixed] = malloc(initsize);
    if(!I2){
        fprintf(stderr, "could not allocate I1\n");
        return -1;
    }

    for(int i = 0; i < m; i++)
        printf("q -> %d\n", q[i]);
    printf("\n");
    for(int i = 0; i < L * m; i++)
        printf("t -> %d\n", t[i]);
    printf("\n");

    uint8_t (*d2)[m][nbytes_fixed] = malloc(initsize), (*e2)[m][nbytes_fixed] = malloc(initsize);
    uint8_t (*d1)[m][nbytes_fixed] = NULL, (*e1)[m][nbytes_fixed] = NULL;
    uint8_t (*d)[m][nbytes_fixed] = NULL, (*e)[m][nbytes_fixed] = NULL;
    if(!d2 || !e2){
        fprintf(stderr, "could not allocate d or e arrays\n");
        return -1;
    }

    int index1, index2;
    int no_pairs = l / 2;
    bool uneven = no_pairs * 2 != l;
    l -= no_pairs;

    int index = 0, subindex = 0, j = 0;
    for(int attribute = 0; attribute < m; attribute++){
        for(int pair = 0; pair < no_pairs; pair++){
            for(int i = 0; i < nbytes_fixed; i++){
                index1 = attribute * L + (pair * 2);
                index2 = index1 + 1;
                d2[pair][attribute][i] = D2(index1, i) ^ (255 * t[index1]) ^ T2[0][j] ^ 255;
                e2[pair][attribute][i] = D2(index2, i) ^ (255 * t[index2]) ^ T2[1][j++] ^ 255;
            }
        }
    }

    uint8_t *recv_arr;
    uint64_t count;

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == initsize){
        d1 = (void *)recv_arr;
        d = d1;
    }
    else{
        fprintf(stderr, "receive d1 from s1 failed\n");
        return -1;
    }
    if(send_8(s1_fd, (uint8_t *)d2, initsize) != 0){
        fprintf(stderr, "send d2 to s1 failed\n");
        return -1;
    }

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == initsize){
        e1 = (void *)recv_arr;
        e = e1;
    }
    else{
        fprintf(stderr, "receive e1 from s1 failed\n");
        return -1;
    }

    if(send_8(s1_fd, (uint8_t *)e2, initsize) != 0){
        fprintf(stderr, "send e2 to s1 failed\n");
        return -1;
    }

    j = 0;
    for(int attribute = 0; attribute < m; attribute++){
        for(int pair = 0; pair < no_pairs; pair++){
            for(int i = 0; i < nbytes_fixed; i++){
                d[pair][attribute][i] = d1[pair][attribute][i] ^ d2[pair][attribute][i];
                e[pair][attribute][i] = e1[pair][attribute][i] ^ e2[pair][attribute][i];
                I2[pair][attribute][i] = (d[pair][attribute][i] & e[pair][attribute][i]) ^ (d[pair][attribute][i] & T2[1][j])
                    ^ (e[pair][attribute][i] & T2[0][j]) ^ T2[2][j];
                j++;
            }
        }
    }
    free(d1);
    free(e1);

    int leftoverindex;
    if(uneven){
        for(int attribute = 0; attribute < m; attribute++){
            for(int i = 0; i < nbytes_fixed; i++){
                leftoverindex = L * (attribute + 1) - 1;
                I2[no_pairs][attribute][i] = D2(leftoverindex, i) ^ (255 * t[leftoverindex]) ^ 255;
            }
        }
    }

    int jcheckpoint, spacing;
    int no_rounds = (int)ceil(log2(l));
    for(int round = 0; round < no_rounds; round++){
        l -= no_pairs;
        spacing = (int)pow(2, round);
        jcheckpoint = j;
        for(int attribute = 0; attribute < m; attribute++){
            for(int pair = 0; pair < no_pairs; pair++){
                index1 = 2*pair*spacing;
                index2 = spacing*(2*pair + 1);
                for(int i = 0; i < nbytes_fixed; i++){
                    d2[pair][attribute][i] = I2[index1][attribute][i] ^ T2[0][j];
                    e2[pair][attribute][i] = I2[index2][attribute][i] ^ T2[1][j++];
                }
            }
        }
        j = jcheckpoint;
        int sendsize = l * m * nbytes_fixed;
        if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == sendsize){
            d1 = (void *)recv_arr;
            d = d1;
        }
        else{
            fprintf(stderr, "receive d1 from s1 failed\n");
            return -1;
        }
        if(send_8(s1_fd, (uint8_t *)d2, sendsize) != 0){
            fprintf(stderr, "send d2 to s1 failed\n");
            return -1;
        }

        if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == sendsize){
            e1 = (void *)recv_arr;
            e = e1;
        }
        else{
            fprintf(stderr, "receive e1 from s1 failed\n");
            return -1;
        }

        if(send_8(s1_fd, (uint8_t *)e2, sendsize) != 0){
            fprintf(stderr, "send e2 to s1 failed\n");
            return -1;
        }

        //servers publish shares, i.e. server 1 sends D1 and E1, server 2 similarly
        for(int attribute = 0; attribute < m; attribute++){
            for(int pair = 0; pair < no_pairs; pair++){
                index1 = 2*pair*spacing;
                for(int i = 0; i < nbytes_fixed; i++){
                    //now both servers have all parts to reconstruct D and E, and thus both calculate:
                    d[pair][attribute][i] = d1[pair][attribute][i] ^ d2[pair][attribute][i];
                    e[pair][attribute][i] = e1[pair][attribute][i] ^ e2[pair][attribute][i];
                    I2[index1][attribute][i] = (d[pair][attribute][i] & e[pair][attribute][i]) ^
                        (d[pair][attribute][i] & T2[1][j]) ^ (e[pair][attribute][i] & T2[0][j]) ^ T2[2][j];
                    j++;
                }
            }
        }
        free(d1);
        free(e1);
    }

    free(d2);
    free(e2);

    //z is intermediate results, Z is final
    //uint8_t (*z2)[nbytes_fixed] = realloc(I2, m * nbytes_fixed * sizeof(uint8_t));
    uint8_t (*z2)[nbytes_fixed] = malloc(m * nbytes_fixed * sizeof(uint8_t));
    for(int attribute = 0; attribute < m; attribute++)
        memcpy(z2[attribute], I2[0][attribute], nbytes_fixed);
    free(I2);

    for(int attribute = 0; attribute < m; attribute++)
        for(int i = 0; i < nbytes_fixed; i++)
            z2[attribute][i] ^= (255 * q[attribute]) ^ 255;

    for(int i = 0; i < m; i++)
        printf("z -> %d\n", z2[i][0] >> 0 & 1);
    printf("\n");

    int intersect_indices[1];
    intersect_indices[0] = 0;
    for(int attribute = 0; attribute < m; attribute++)
        t[attribute] = 1;

    no_multis_bytes = (m - 1) * nbytes_fixed;
    uint8_t (*T2_2)[no_multis_bytes] = malloc(3 * no_multis_bytes * sizeof(uint8_t));
    for(int k = 0; k < 3; k++)  //tedious necessary rearrangement of triples
        memcpy(T2_2[k], &T2[k][j], no_multis_bytes);

    int ret = intersectminus(n_fixed, m, m, no_multis_bytes, z2, T2_2, Z2, intersect_indices, t);
    printf("printing Z:\n");
    printboolvec(*Z2, n_fixed);
    free(z2);
    free(T2_2);
    return ret;

}


static void cout_size_reduction(int batch_bytes, int max_depth, uint8_t (*S)[batch_bytes * 8], uint8_t **choices, int *js, int *js_acc){
    //int batch_size = batch_bytes * 8;

    //server2
    //int c = 0;
    int noOTs_j = js_acc[max_depth];
    randombytes_buf((uint8_t *)S, noOTs_j * batch_bytes);
    *choices = (uint8_t *)S;

    /*for(int depth = 0; depth < max_depth; depth++)
        for(int j = 0; j < js[depth]; j++)
            for(int i = 0; i < batch_bytes; i++)
                choices[c++] = S[js_acc[depth] + j][i];*/

}

static void cout_product_sharing(int batch_bytes, uint8_t (*s)[batch_bytes], uint8_t **choices, int noOTs_bytes){
    
    //server2
    //int c = 0;
    randombytes_buf((uint8_t*)s, noOTs_bytes);
    *choices = (uint8_t*)s;

    /*for(int i = 0; i < batch_bytes; i++)
        for(int j = 0; j < expon; j++)
            choices[c++] = s[j][i];*/
}

static int couteauPrepSR(int batch_bytes, int max_depth, uint8_t (*S)[batch_bytes], uint32_t (*B)[batch_bytes * 8], int *js, int *js_acc){
    
    if(js[0] < 2)
        return 0;
    
    int batch_size = batch_bytes * 8;

    int noOTs_j = js_acc[max_depth];
    int noOTs_SR = noOTs_j * batch_size, noOTs_SR_bytes = noOTs_j * batch_bytes;

    if(max_depth < 1)
        return -1;
    
    uint32_t *output = (uint32_t *)B;
    uint8_t *choices = NULL;
    
    cout_size_reduction(batch_bytes, max_depth, S, &choices, js, js_acc);
    OTeRecv32(output, choices, noOTs_SR);
    B = (void *)output;

    return 0;
}

static int couteauPrepPS(int batch_bytes, uint8_t (*s)[batch_bytes], uint8_t (*b)[batch_bytes]){

    int batch_size = batch_bytes * 8;
    int noOTs_PS = expon * batch_size, noOTs_PS_bytes = expon * batch_bytes;

    uint8_t *output = (uint8_t *)b;
    uint8_t *choices = NULL;

    cout_product_sharing(batch_bytes, s, &choices, noOTs_PS_bytes);
    OTeRecv1(output, choices, noOTs_PS);
    b = (void *)output;

    return 0;
}

static int couteauPrep(int batch_bytes, int max_depth, uint8_t (*S)[batch_bytes], uint32_t (*B)[batch_bytes * 8], uint8_t (*s)[batch_bytes], uint8_t (*b)[batch_bytes], int *js, int *js_acc){

    if(js[0] < 2){
        printf("skipping couteauprep\n");
        return 0;
    }

    if(max_depth > 0){  // if (need to do size reduction)
        if(couteauPrepSR(batch_bytes, max_depth, S, B, js, js_acc) == -1){
            fprintf(stderr, "failure in couteauPrepSR()\n");
            return -1;
        }
    } else{ printf("skipping size_reduction\n"); S = NULL, B = NULL; }

    if(couteauPrepPS(batch_bytes, s, b) == -1){
        fprintf(stderr, "failure in couteauPrepPS()\n");
        return -1;
    }
    return 0;
}

static int couteauHybridPrep(int batch_bytes, int max_depth, uint8_t (*S)[batch_bytes], uint32_t (*B)[batch_bytes * 8], int *js, int *js_acc){
    if(js[0] < 2){
        printf("skipping couteauHybridPrep()\n");
        return 0;
    }

    if(max_depth > 0){  // if (need to do size reduction)
        if(couteauPrepSR(batch_bytes, max_depth, S, B, js, js_acc) == -1){
            fprintf(stderr, "failure in couteauPrepSR()\n");
            return -1;
        }
    } else{ printf("skipping size_reduction\n"); S = NULL, B = NULL; }

    if(verbose) printf("finished couteauHybridPrep()\n");
    return 0;
}

static int couteauSR(int n_fixed, int max_depth, uint8_t (**YS)[tobytes(n_fixed)], uint8_t (*S)[tobytes(n_fixed)], uint32_t (*B)[n_fixed], int *intersect_indices, bool *t, int *js, int *js_acc){
    
    int l = js[0];
    int nbytes_fixed = tobytes(n_fixed);
    int noOTs_j = js_acc[max_depth];
    uint8_t (*ys)[nbytes_fixed] = malloc(nbytes_fixed * (noOTs_j + rsize));
    memset(ys, 0, nbytes_fixed * (noOTs_j + rsize));
    
    if(!ys){
        printf("could not allocate ys\n");
        return -1;
    }
    
    int indexlen = l / L;
    int acc;
    
    //server1 sets x1 = x for every record
    for(int i = 0; i < nbytes_fixed; i++)
        for(int j = 0; j < indexlen; j++)
            for(int k = 0; k < L; k++)
                ys[j * L + k][i] = D2(intersect_indices[j] * L + k, i) ^ (255 * t[j * L + k]);

    if(l == 1 || max_depth == 0){
        *YS = realloc(ys, rsize * nbytes_fixed);
        printf("skipping size reduction\n");
        return 0;
    }
    for(int depth = 0; depth < max_depth; depth++){
        int arr_size = nbytes_fixed * js[depth];
        uint8_t (*z2)[nbytes_fixed] = malloc(arr_size), (*z1)[nbytes_fixed] = NULL, (*z)[nbytes_fixed] = z1; //reuse z1 array
        if(!z2){
            printf("could not allocate z1\n");
            return -1;
        }
        //server2 sends for each record: z2 = s[i] ^ y[i];
        for(int i = 0; i < nbytes_fixed; i++)
            for(int j = 0; j < js[depth]; j++)
                z2[j][i] = S[js_acc[depth] + j][i] ^ ys[js_acc[depth] + j][i];
        
        //servers exchange z1 and z2
        uint8_t *recv_arr;
        uint64_t count;
        if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == arr_size)
            z1 = (void *)recv_arr;
        else{
            fprintf(stderr, "receive z1 from s1 failed\n");
            return -1;
        }

        if(send_8(s1_fd, (uint8_t *)z2, arr_size) != 0){
            fprintf(stderr, "send z2 to s1 failed\n");
            return -1;
        }

        //and calculate z as z = z1 ^ z2
        for(int i = 0; i < nbytes_fixed; i++)
            for(int j = 0; j < js[depth]; j++)
                z[j][i] = z1[j][i] ^ z2[j][i];
        
        //server1 calculates what will become xs[i+1]
        bool b;
        int byte = 0, bit = 0;
        for(int i = 0; i < n_fixed; i++){
            if(bit > 7){
                bit = 0;
                byte++;
            }
            acc = 0;
            for(int j = 0; j < js[depth]; j++){
                b = z[j][byte] >> bit & 1;
                acc += (int)pow(-1, b) * B[js_acc[depth] + j][i] + b;
            }
            acc = FF_convert(acc, js[depth] + 1);
            for(int j = 0; j < js[depth + 1]; j++)
                ys[js_acc[depth + 1] + j][byte] += (acc >> j & 1) << bit;
            bit++;
        }
        free(z1);
        free(z2);
    }
    *YS = &ys[js_acc[max_depth]];
    YS = realloc(ys, rsize * nbytes_fixed);
    return 0;
}

static int couteauPS(int n_fixed, int max_depth, uint8_t **Z2, uint8_t (*YS)[tobytes(n_fixed)], uint8_t (*s)[tobytes(n_fixed)], uint8_t (*b)[tobytes(n_fixed)]){

    int nbytes_fixed = tobytes(n_fixed);
    bool I[expon][rsize];
    powset(rsize, I, expon);

    *Z2 = malloc(nbytes_fixed * sizeof(uint8_t));
    if(!Z2){
        printf("could not allocate Z1\n");
        return -1;
    }
    //server2
    uint8_t *beta = malloc(nbytes_fixed), *alpha = NULL,
    (*Beta)[nbytes_fixed] = malloc(nbytes_fixed * expon), (*Alpha)[nbytes_fixed] = NULL;

    if(!beta || !Beta){
        printf("could not allocate beta or Beta\n");
        return -1;
    }

    uint8_t acc1;
    for(int i = 0; i < nbytes_fixed; i++){
        for(int k = 0; k < expon; k++){
            acc1 = 255;
            for(int j = 0; j < rsize; j++){
                if(!I[k][j])
                    acc1 &= YS[j][i];
            }
            Beta[k][i] = s[k][i] ^ acc1;
        }
    }
    randombytes_buf(beta, nbytes_fixed);

    //servers send each other alpha and beta (+Alpha and Beta)
    uint8_t *recv_arr;
    uint64_t count;
    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == nbytes_fixed)
        alpha = (void *)recv_arr;
    else{
        fprintf(stderr, "receive alpha from s1 failed\n");
        return -1;
    }
    if(send_8(s1_fd, (uint8_t *)beta, nbytes_fixed) != 0){
        fprintf(stderr, "send beta to s1 failed\n");
        return -1;
    }

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == nbytes_fixed * expon)
        Alpha = (void *)recv_arr;
    else{
        fprintf(stderr, "receive Alpha from s1 failed\n");
        return -1;
    }
    if(send_8(s1_fd, (uint8_t *)Beta, nbytes_fixed * expon) != 0){
        fprintf(stderr, "send Beta to s1 failed\n");
        return -1;
    }

    //server2
    uint8_t acc2;
    for(int i = 0; i < nbytes_fixed; i++){
        acc1 = 0;
        acc2 = 255;
        for(int k = 0; k < expon; k++)
            acc1 ^= b[k][i] ^ (Alpha[k][i] & s[k][i]);
        for(int j = 0; j < rsize; j++)
            acc2 &= YS[j][i];
        *Z2[i] = acc1 ^ acc2 ^ alpha[i] ^ beta[i];
    }

    free(YS);
    free(alpha);
    free(beta);
    free(Alpha);
    free(Beta);

    return 0;
}

static int couteauHybridET(int n_fixed, int max_depth, uint8_t **Z2, uint8_t (*S)[tobytes(n_fixed)], uint32_t (*B)[n_fixed], int no_multis_bytes, uint8_t (*T2)[no_multis_bytes], int *intersect_indices, bool *t, int *js, int *js_acc){
    if(js[0] < 1)
        return -1;
    int nbytes_fixed = tobytes(n_fixed);
    uint8_t (*YS)[nbytes_fixed] = NULL;
    couteauSR(n_fixed, max_depth, &YS, S, B, intersect_indices, t, js, js_acc);

    intersect_indices[0] = 0;
    for(int i = 0; i < rsize; i++)
        t[i] = 0;

    int ret = intersectminus(n_fixed, rsize, rsize, no_multis_bytes, YS, T2, Z2, intersect_indices, t);
    free(YS);
    return ret;
}

static int couteauET(int n_fixed, int max_depth, uint8_t **Z2, uint8_t (*S)[tobytes(n_fixed)], uint32_t (*B)[n_fixed], uint8_t (*s)[tobytes(n_fixed)], uint8_t (*b)[tobytes(n_fixed)], int *intersect_indices, bool *t, int *js, int *js_acc){
    if(js[0] < 1)
        return -1;
    
    int nbytes_fixed = tobytes(n_fixed);
    uint8_t (*YS)[nbytes_fixed] = NULL;

    if(couteauSR(n_fixed, max_depth, &YS, S, B, intersect_indices, t, js, js_acc) == -1){
        fprintf(stderr, "failure in couteauSR\n");
        return -1;
    }
    if(couteauPS(n_fixed, max_depth, Z2, YS, s, b) == -1){
        fprintf(stderr, "failure in couteauPS\n");
        return -1;
    }
    return 0;
}

static void generate_records(){
    //randombytes_buf(D, nbytes * line);
    memset(D, 0, nbytes * line);
    uint32_t r_vec[m][n];
    random_vector((uint32_t*)r_vec, m * n, (1 << L) - 1);
    for(int attribute = 0; attribute < m; attribute++){
        for(int i = 0; i < n; i++){
            bool temp[L];
            int_to_vector((int)r_vec[attribute][i], temp, L);
            for(int k = 0; k < L; k++)
                D2(attribute * L + k, i/8) |= temp[k] << i%8;
        }
    }
}
//dabitgen algorithm according to [1] but parallelised
static int generate_dabits(int batch_bytes, uint8_t *B2, uint32_t *A2){
    int batch_size = batch_bytes * 8;
    
	//s1 chooses n random bits B1
	//s1 chooses n random field elements X and sets y1 = -x mod p for each one

	//s2 chooses n random bits B2
    randombytes_buf(B2, batch_bytes);

	//s1 acts as OT sender, sending (x, x + b1), s2 acts as receiver with choice bit b2
    
    uint8_t *choices = B2;  // choice bit
    uint32_t *output = A2;   // reuse A2 array for output

    OTeRecv32(output, choices, batch_size);
	//both servers compute a_i = b_i - 2*y_i and output values
    int byte = 0, bit = 0;
    for(int i = 0; i < batch_size; i++){
        if(bit > 7){
            bit = 0;
            byte++;
        }
        A2[i] = FF_convert((B2[byte] >> bit++ & 1) - (2 * A2[i]), FF_size);
    }
    if(verbose)
        printf("finished generating dabits\n");
    return 0;
}

// pre-compute a batch of beaver triples in parallel
static int generate_beaver_triples(int batch_bytes, uint8_t (*T2)[batch_bytes]){
    int batch_size = batch_bytes * 8;
    if(batch_size == 0)
        return 0;
	//server 1 samples 'batch_size' bit doubles (a1, b1) plus 'batch_size' random bits R1 for the OTs

    //server 2 does the same
    
    uint8_t* s2_R = malloc(batch_bytes * sizeof(uint8_t));
    if(!s2_R){
        printf("could not allocate space\n");
        return -1;
    }
    randombytes_buf(s2_R, batch_bytes);
    randombytes_buf(T2[0], 2 * batch_bytes);

	//perform 2 OTs
    uint8_t *messages1 = s2_R, *messages2 = malloc(batch_bytes * sizeof(uint8_t));
    uint8_t *choices = T2[1], *output = malloc(batch_bytes * sizeof(uint8_t));

    if(!messages2 || !output){
        printf("could not allocate space for messages2 or output\n");
        return -1;
    }
	for(int i = 0; i < batch_bytes; i++)
		messages2[i] = s2_R[i] ^ T2[0][i];
    
    OTeRecv1(output, choices, batch_size);
    OTeSend1(messages1, messages2, batch_size);
    
    for(int i = 0; i < batch_bytes; i++)
		//server 1 acts as the sender, sending (r1, r1 ^ a1)
		//server 2 selects with b2 to learn x2 = a1b2 ^ r1
		//x2 = oblivious_transfer(s1_R[i], s1_R[i] ^ s1_triples[j], s2_triples[j + 1]);
		//server 2 calculates c2 as follows, according to the standard protocol [2]
		//now reverse roles
		//x1 = oblivious_transfer(s2_R[i], s2_R[i] ^ s2_triples[j], s1_triples[j + 1]);	
		T2[2][i] = output[i] ^ s2_R[i] ^ (T2[0][i] & T2[1][i]);

    free(messages1);
    free(messages2);
    free(output);

    if(verbose)
        printf("finished generating beaver triples\n");
    return 0;
}

//boolean-to-arithmetic conversion for an array of bits seen in [2], but parallelised
static int b2a_convert(int n_fixed, uint32_t *output2, uint8_t *input2, uint8_t *dab2B, uint32_t *dab2A){
    int nbytes_fixed = tobytes(n_fixed);
	//server 1 calculates intermediate values V1


	//server 2 does likewise
	uint8_t *V2 = input2, *V1 = NULL, *V = dab2B; //reuse arrays for efficiency

	for(int i = 0; i < nbytes_fixed; i++)
        V2[i] = input2[i] ^ dab2B[i];
	
	//servers share V in the clear
    uint8_t *recv_arr;
    uint64_t count;
    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == nbytes_fixed)
        V1 = recv_arr;
    else{
        fprintf(stderr, "receive V1 from s1 failed\n");
        return -1;
    }
    if(send_8(s1_fd, V2, nbytes_fixed) != 0){
        fprintf(stderr, "send V2 to s1 failed\n");
        return -1;
    }

	for(int i = 0; i < nbytes_fixed; i++)
		V[i] = V1[i] ^ V2[i];

	//server 1 calculates output x as x = v + [b]^A_1 - 2v[b]^A_1 ([b]^A is the arithmetic share of the dabit)

	//server 2 calculates x as x = [b]^A_2 - 2v[b]^A_2
    bool b;
    int byte = 0, bit = 0;
    for(int i = 0; i < n_fixed; i++){
        if(bit > 7){
            bit = 0;
            byte++;
        }
        b = V[byte] >> bit++ & 1;
        output2[i] = FF_convert(dab2A[i] - (2 * b * dab2A[i]), FF_size);
    }
    free(V1);
    return 0;
}

static int verify(uint8_t *arr){
    int no_multis = (L - 1) * m;
    uint8_t T2[3][no_multis];
    if(generate_beaver_triples(no_multis, T2) == -1){
        fprintf(stderr, "error in generate_beaver_triples()\n");
        return -1;
    }
    univ_start = clock();

    printboolvec(arr, 8);
    uint8_t Z2[m], *Z1;
    bool R[line];
    bytestobools(R, arr, line);
    bool t[L];
    for(int j = 0; j < L; j++)
        t[j] = 1;

    for(int i = 0; i < m; i++){
        //fprintf(stderr, "i = %d\n", i);
        int index [1];
        index[0] = 0;
        uint8_t *z = NULL;
        uint8_t alt_D[L][1];
        for(int j = 0; j < L; j++){
            alt_D[j][0] = R[i * L + j];
            //printf("%d\n", alt_D[j][0]);
        }
        if(intersectminus(1, L, L, no_multis, alt_D, &T2[no_multis], &z, index, t) == -1){
            fprintf(stderr, "error in intersectminus()\n");
            return -1;
        }
        Z2[i] = z[0] & 1;
        printf("%d\n", Z2[i]);
        free(z);
    }

    uint8_t *recv_arr;
    uint64_t count, exp_count = m;

    if(send_8(s1_fd, Z2, exp_count) != 0)
        return -1;

    if(receive_8(s1_fd, &recv_arr, &count) == 0 && count == exp_count)
        Z1 = recv_arr;
    else{
        fprintf(stderr, "receive Z1 from s1 failed, no. elements received = %" PRIu64 "\n", count);
        return -1;
    }

    for(int i = 0; i < m; i++)
        //printf("%d\n", Z1[i] ^ Z2[i]);
        if(Z1[i] ^ Z2[i])
            return 0;
    printf("---------------------------------\n");
    univ_end = clock();
    univ_final = (double)(univ_end - univ_start) / CLOCKS_PER_SEC;
    printf("total time = %f\n", univ_final);
    return 1;
}

static int client_update(uint8_t *arr, uint64_t count){
    int linebytes = tobytes(line);
    if(count == linebytes){
        if(!verify(arr)){ fprintf(stderr, "cheating client, the vector of all 1s is not allowed\n"); return -1;};
        int nbyte, nbit;
        int byte = 0, bit = 0;
        indextobyteandbit(&nbyte, &nbit, n++);
        int oldnbyte = nbytes;
        nbytes = tobytes(n);
        if(nbytes > oldnbyte){
            D2_cols++;
            D = realloc(D, D2_cols * line);
            if(!D){
                printf("error reallocating D2\n");
                return -1;
            }
        }
        if(n + 1 > FF_size){
            fprintf(stderr, "n bigger than FF_size\n");
            FF_size++;
            return -1;
        }
        for(int i = 0; i < line; i++){
            if(bit > 7){
                bit = 0;
                byte++;
            }
            D2(i, nbyte) |= (arr[byte] >> bit & 1) << nbit;
        }
        printf("record added to database\n");
    }
    else fprintf(stderr, "invalid record bitlength, must be %d bits\n", line);
    return 0;
}

static void* client_query_thread(void *arg){
    int n_fixed = n; //fix n at this point so it doesn't change during computation
    int nbytes_fixed = nbytes;
    query_thread_args *args = arg;
    int client_fd = args->client_fd;
    uint8_t *arr = args->arr;
    uint64_t count = args->count;
    int intersection_indices[m];

    int max_q_len_bytes = 16;
    int max_q_len = max_q_len_bytes * 8;

    if(m > max_q_len){
        fprintf(stderr, "need bigger buffer for m\n");
        return NULL;
    }

    int index_len, query_len;
    if(intersect_version == INTERSECT_MINUS || cout)
        index_len = bchartoindexvec(intersection_indices, arr, max_q_len);
    else index_len = m;
    query_len = index_len * L;

    if(count != 1 + max_q_len_bytes + tobytes(query_len)){
        fprintf(stderr, "message len should be 1 (message type) + 16 (q) + %d (t), actual len = %ld\n", tobytes(query_len), count);
        return NULL;
    }
    bool t[query_len];
    bytestobools(t, &arr[max_q_len_bytes], query_len);

    /*fprintf(stderr, "index_len = %d, query_len = %d\n", index_len, query_len);
    for(int i = 0; i < query_len; i++)
        printf("%d\n", t[i]);
    for(int i = 0; i < index_len; i++)
        printf("%d\n", intersection_indices[i]);*/

    uint8_t *dab2B = malloc(nbytes_fixed * sizeof(uint8_t));
    uint32_t *dab2A = malloc(8 * nbytes_fixed * sizeof(uint32_t));
    if(!dab2B || !dab2A){
        printf("error allocating dabits\n");
        return NULL;
    }

    if(generate_dabits(nbytes_fixed, dab2B, dab2A)){
        printf("failed to generate dabits\n");
        return NULL;
    }
    uint8_t *Z2 = NULL;
    if(cout){
        int j = query_len, depth = 0;
        int noOTs_j = 0;
        int js[32], js_acc[32];
        js[0] = j;
        js_acc[0] = 0;

        while(j > rsize){
            if(depth > 32){
                printf("need bigger js array\n");
                return NULL;
            }
            noOTs_j += j;
            j = (int)ceil(log2(j)) + 1;
            depth++;
            js[depth] = j;
            js_acc[depth] = noOTs_j;
        }

        expon = (int)pow(2, rsize) - 2;
        if(light){
            if(!benchmarking){
                uint8_t (*S)[nbytes_fixed] = malloc(noOTs_j * nbytes_fixed * sizeof(uint8_t));
                uint32_t (*B)[nbytes_fixed * 8] = malloc(noOTs_j * (nbytes_fixed * 8) * sizeof(uint32_t));
                if(!S || !B){
                    fprintf(stderr, "could not allocate S or B\n");
                    return NULL;
                }
                int no_multis_bytes = nbytes_fixed * (rsize - 1);
                uint8_t (*T2)[no_multis_bytes] = malloc(3 * no_multis_bytes * sizeof(uint8_t));
                if(!T2){
                    fprintf(stderr, "could not allocate T2\n");
                    return NULL;
                }
                if(generate_beaver_triples(no_multis_bytes, T2) == -1){
                    fprintf(stderr, "error in generate_beaver_triples()\n");
                    return NULL;
                }
                if(couteauHybridPrep(nbytes_fixed, depth, S, B, js, js_acc) == -1){
                    fprintf(stderr, "error in couteauPrep()\n");
                    return NULL;
                }
                if(couteauHybridET(n_fixed, depth, &Z2, S, B, no_multis_bytes, T2, intersection_indices, t, js, js_acc) == -1){
                    fprintf(stderr, "error in couteauHybridET()\n");
                    return NULL;
                }
                free(S);
                free(B);
                free(T2);
            }
            else{/*
                if(benchmarktype == 0)
                    return cout_light_offline_tests(depth, query_len, noOTs_j, js);
                else return cout_light_online_tests(depth, query_len, V1, V2, noOTs_j, js);*/
            }
        }
        else{   //coutfull
            if(!benchmarking){
                uint8_t (*S)[nbytes_fixed] = malloc(noOTs_j * nbytes_fixed * sizeof(uint8_t));
                uint32_t (*B)[nbytes_fixed * 8] = malloc(noOTs_j * (nbytes_fixed * 8) * sizeof(uint32_t));
                if(!S || !B){
                    fprintf(stderr, "could not allocate S or B\n");
                    return NULL;
                }
                uint8_t (*s)[nbytes_fixed] = malloc(expon * nbytes_fixed * sizeof(uint8_t)),
                (*b)[nbytes_fixed] = malloc(expon * nbytes_fixed * sizeof(uint8_t));
                if(!s || !b){
                    fprintf(stderr, "could not allocate s or b\n");
                    return NULL;
                }
                double start_time = 0, end_time = 0, final_time;
                start_time = clock();
                if(couteauPrep(nbytes_fixed, depth, S, B, s, b, js, js_acc) == -1){
                    fprintf(stderr, "error in couteauPrep()\n");
                    return NULL;
                }
                end_time = clock();

                if(couteauET(n_fixed, depth, &Z2, S, B, s, b, intersection_indices, t, js, js_acc) == -1){
                    fprintf(stderr, "error in couteauET()\n");
                    return NULL;
                }
                final_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
                //final_time += artificial_delay;
                printf("%.2f\n", final_time);
                free(s);
                free(b);
                free(S);
                free(B);
            }
            else{
                /*if(benchmarktype == 0)
                    return cout_full_offline_tests(depth, query_len, noOTs_j, js);
                else return cout_full_online_tests(depth, query_len, V1, V2, noOTs_j, js);*/
            }
        }
    }
    else{   //intersect
        if(!benchmarking){
            int no_multis_bytes = tobytes(n_fixed) * (query_len - 1);
            uint8_t (*T2)[no_multis_bytes] = malloc(3 * no_multis_bytes * sizeof(uint8_t));
            if(!T2){
                fprintf(stderr, "error allocating T1\n");
                return NULL;
            }
            double start_time = 0, end_time = 0, final_time;
            start_time = clock();
            if(generate_beaver_triples(no_multis_bytes, T2) == -1){
                fprintf(stderr, "error in generate_beaver_triples()\n");
                return NULL;
            }
            end_time = clock();
            if(intersect_version == INTERSECT_MINUS){
                if(intersectminus(n_fixed, query_len, L, no_multis_bytes, NULL, T2, &Z2, intersection_indices, t) == -1){
                    fprintf(stderr, "error in intersectminus()\n");
                    return NULL;
                }
            }
            else{
                bool q[m];
                bytestobools(q, arr, m);
                if(intersectfull(n_fixed, no_multis_bytes, T2, &Z2, q, t) == -1){
                    fprintf(stderr, "error in intersectfull()\n");
                    return NULL;
                }
            }

            final_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            //final_time += artificial_delay;
            //printf("%.2f\n", final_time);
            free(T2);
        }
        else{/*
            if(benchmarktype == 0)
                return intersect_offline_tests(query_len);
            else return intersect_online_tests(query_len, V1, V2, Z1, Z2);*/
        }
    }
    //printboolvec(Z2, n_fixed);

    uint32_t *Z2_arith = malloc(n_fixed * sizeof(uint32_t));//arithmetic shares of the intersection values, Z1 and Z2
    if(!Z2_arith){
        fprintf(stderr, "could not allocate Z2_arith\n");
        return NULL;
    }

	b2a_convert(n_fixed, Z2_arith, Z2, dab2B, dab2A);

    free(Z2);
    free(dab2B);
    free(dab2A);

	uint32_t s2_total = aggregate_1D(Z2_arith, FF_size, n_fixed);
    printf("s2_total = %d\n", s2_total);
    free(Z2_arith);

    int response_len = 1 * sizeof(uint8_t);
    uint8_t *response = malloc(response_len);
    response[0] = gc_threshold_check(2, s2_total, FF_size, THRESHOLD, target_addr, GCPORT);
    //response[0] = 0;
    //printf("%d\n", response[0]);

    free(args->arr - 1);
    free(args);

    query_thread_result *result = malloc(sizeof(query_thread_result));
    result->client_fd = client_fd;
    result->response = response;
    result->response_len = response_len;
    // Post result to event loop
    pthread_mutex_lock(&result_queue_mutex);
    enqueue_result(&result_queue, result);
    pthread_mutex_unlock(&result_queue_mutex);

    uint64_t val = 1;
    eventfd_write(exchange_eventfd, val);

    return NULL;
}


static void client_query(connection_t *c, uint8_t *arr, uint64_t count){

    printf("starting client_query\n");
    query_thread_args *args = malloc(sizeof(query_thread_args));
    args->client_fd = c->fd;
    args->arr = arr;
    args->count = count;

    pthread_t t;
    pthread_create(&t, NULL, client_query_thread, args);
    pthread_detach(t);
}


/* -------------------------------------------------------------------------
 * I/O handlers
 * -------------------------------------------------------------------------
 *
 */

static int connection_enqueue(connection_t *c, const uint8_t *data, size_t len){
    write_chunk_t *chunk = malloc(sizeof(write_chunk_t));
    if (!chunk) return -1;
    chunk->buf  = malloc(len);
    if (!chunk->buf) { free(chunk); return -1; }
    memcpy(chunk->buf, data, len);
    chunk->len  = len;
    chunk->off  = 0;
    chunk->next = NULL;

    if (c->write_tail) {
        c->write_tail->next = chunk;
        c->write_tail       = chunk;
    } else {
        // List was empty
        c->write_head = chunk;
        c->write_tail = chunk;
    }
    return 0;
}

// Returns 0 if a complete message is ready, 1 if still accumulating, -1 on error.
static int feed_parser(parser_t *p, const uint8_t *data, size_t len,
                       uint8_t **out_arr, uint64_t *out_count){
    while (len > 0) {
        if (p->state == PARSE_READING_HEADER) {
            size_t need = sizeof(p->header_buf) - p->header_got;
            size_t take = len < need? len: need;
            memcpy(p->header_buf + p->header_got, data, take);
            p->header_got += take;
            data          += take;
            len           -= take;

            if (p->header_got < sizeof(p->header_buf)){
                printf("still waiting for rest of header\n");
                return 1;
            }

            // Header complete — decode and validate
            p->count = decode_uint64_be(p->header_buf);
            if (p->count == 0 || p->count > MAX_ARRAY_ELEMENTS)
                return -1;
            //printf("count = %ld\n", p->count);
            p->payload = malloc(p->count);
            if (!p->payload) return -1;
            p->payload_got = 0;
            p->state       = PARSE_READING_PAYLOAD;
        }

        if (p->state == PARSE_READING_PAYLOAD) {
            size_t need = p->count - p->payload_got;
            size_t take = len < need? len: need;
            memcpy(p->payload + p->payload_got, data, take);
            p->payload_got += take;
            data           += take;
            len            -= take;

            if (p->payload_got < p->count){
                printf("still waiting for rest of payload\n");
                return 1;
            }

            // Message complete — hand off to caller
            *out_arr   = p->payload;
            *out_count = p->count;

            // Reset for next message
            p->payload     = NULL;
            p->payload_got = 0;
            p->header_got  = 0;
            p->state       = PARSE_READING_HEADER;
            return 0;
        }
    }
    return 1;
}

static void handle_write(connection_t *c){
    while (c->write_head) {
        write_chunk_t *chunk = c->write_head;

        while (chunk->off < chunk->len){
            ssize_t en = send(c->fd,
                             chunk->buf + chunk->off,
                             chunk->len - chunk->off, 0);
            if (en > 0) { chunk->off += (size_t)en; continue; }
            if (errno == EAGAIN || errno == EWOULDBLOCK) return; // wait for next EPOLLOUT
            connection_close(c->fd);
            return;
        }

        // Chunk fully sent — pop it from the list
        c->write_head = chunk->next;
        if (!c->write_head)
            c->write_tail = NULL;   // list now empty
        free(chunk->buf);
        free(chunk);
    }

    // All chunks flushed — disable EPOLLOUT
    epoll_mod(c->fd, EPOLLIN | EPOLLRDHUP | EPOLLET);
}

static void handle_exchange_complete(){
    uint64_t val;
    eventfd_read(exchange_eventfd, &val);

    pthread_mutex_lock(&result_queue_mutex);
    query_thread_result *result = dequeue_result(&result_queue);
    pthread_mutex_unlock(&result_queue_mutex);

    connection_t *c = &conn_table[result->client_fd];
    connection_enqueue(c, result->response, result->response_len);
    handle_write(c);

    free(result->response);
    free(result);
}

static void handle_message(connection_t *c, uint8_t *arr, uint64_t count){
    if(count < 2){
        fprintf(stderr, "not enough elements\n");
        return;
    }
    uint8_t mtype = arr[0];
    if(mtype == 0){
        client_update(&arr[1], count - 1);
        free(arr);
    }
    else if(mtype == 1) client_query(c, &arr[1], count);
    else{
        fprintf(stderr, "message type must be 0 (update) or 1 (query)\n");
        free(arr);
    }
}

static void handle_read(connection_t *c){
    uint8_t buf[RECV_BUF_SIZE];
    while(true){
        ssize_t en = recv(c->fd, buf, sizeof(buf), 0);
        if(en > 0){
            uint8_t *arr = NULL;
            uint64_t count = 0;
            int rc = feed_parser(&c->parser, buf, (size_t)en, &arr, &count);
            if(rc == -1){
                fprintf(stderr, "fd=%d parse error\n", c->fd);
                connection_close(c->fd);
                return;
            }
            if(rc == 0){
                // Complete message — equivalent to recv_uint8_array() success
                handle_message(c, arr, count);
            }
            continue;
        }
        if(en == 0){ connection_close(c->fd); return; }
        if(errno == EAGAIN || errno == EWOULDBLOCK){ break; }
        perror("recv");
        connection_close(c->fd);
        return;
    }
}


static void connection_accept(int listen_fd){
    /*
     * Edge-triggered epoll: we MUST drain all pending accepts in a loop,
     * otherwise we'll miss connections until the next event.
     */
    while(true){
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        int client_fd = accept4(listen_fd, (struct sockaddr *)&peer,
                                &peer_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;          /* No more pending connections. */
            perror("accept4");
            break;
        }

        if (client_fd >= MAX_CONNECTIONS) {
            fprintf(stderr, "fd %d exceeds MAX_CONNECTIONS — dropping\n",
                    client_fd);
            close(client_fd);
            continue;
        }

        /* Enable TCP_NODELAY for latency-sensitive traffic (optional). */
        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        connection_t *c = &conn_table[client_fd];
        c->fd    = client_fd;
        c->conn_state = CONN_ACTIVE;

        /*
         * EPOLLET  — edge-triggered (fire once per state change)
         * EPOLLIN  — notify when data arrives
         * EPOLLOUT — notify when socket is writable (enable when you have
         *            buffered data to send; disable otherwise to avoid
         *            busy-looping)
         * EPOLLRDHUP — peer closed the write half of the connection
         */
        if (epoll_add(client_fd, EPOLLIN | EPOLLRDHUP | EPOLLET) == -1) {
            perror("epoll_add");
            connection_close(client_fd);
            continue;
        }
        active_count++;
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, addr_str, sizeof(addr_str));
        printf("New connection: fd=%d from %s:%d\n",
               client_fd, addr_str, ntohs(peer.sin_port));
    }
}



/* -------------------------------------------------------------------------
 * Signal handler
 * ---------------------------------------------------------------------- */


static void begin_graceful_shutdown(int listen_fd){
    printf("Graceful shutdown initiated — draining %d connections "
           "(timeout %ds)\n", active_count, GRACEFUL_TIMEOUT_SECS);

    // Stop accepting new connections
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, listen_fd, NULL);
    close(listen_fd);

    // Signal EOF to every connected client
    for (int fd = 0; fd < MAX_CONNECTIONS; fd++) {
        if (conn_table[fd].conn_state == CONN_ACTIVE) {
            conn_table[fd].conn_state = CONN_CLOSING;
            shutdown(fd, SHUT_WR);  // sends FIN; we can still recv()
        }
    }
}

static void event_loop(int listen_fd){
    struct epoll_event events[MAX_EVENTS];
    int listen_fd_open = 1;

    while (running) {
        // Handle shutdown request
        if (shutdown_requested && listen_fd_open) {
            begin_graceful_shutdown(listen_fd);
            listen_fd_open = 0;
        }

        // If all connections drained, we're done
        if (shutdown_requested && active_count == 0)
            break;

        // Calculate epoll timeout
        int timeout_ms = -1;  // block indefinitely by default
        if (shutdown_requested) {
            int secs_left = (int)(shutdown_deadline - time(NULL));
            if (secs_left <= 0) {
                printf("Timeout expired — force-closing %d connections\n",
                       active_count);
                break;
            }
            timeout_ms = secs_left * 1000;
        }

        int rc = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout_ms);
        if (rc == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < rc; i++) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            if (fd == listen_fd) { connection_accept(listen_fd); continue; }
            if (fd == exchange_eventfd) { handle_exchange_complete();   continue; }
            if (ev & (EPOLLERR | EPOLLHUP))  { connection_close(fd); continue; }

            connection_t *c = &conn_table[fd];
            if (c->conn_state == CONN_FREE) continue;

            if (ev & EPOLLRDHUP) { connection_close(fd); continue; }
            if (ev & EPOLLIN)    handle_read(c);
            if ((ev & EPOLLOUT) && c->conn_state != CONN_FREE) handle_write(c);
        }
    }
}

//server 1
int main(int argc, char* argv[]){
	if(sodium_init() < 0){
		printf("Error initialising sodium library\n");
                return 1;
	}
    if(s1_connect() == -1)
        return -1;
    if(s1_hello() == -1)
        return -1;
    nbytes = tobytes(n);
    line = m * L;
    D2_cols = nbytes;
    D = malloc(D2_cols * line);
    if(!D){
        printf("could not allocate D2\n");
        return -1;
    }
    memset(D, 0, D2_cols * line);

	//generate_records();

    if(verbose) printf("FF_size = %" PRIu32 "\n", FF_size);
	if(verbose) if(print_records() == -1) return -1;

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);   /* Ignore broken-pipe; check write() return */

    memset(conn_table, 0, sizeof(conn_table));

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if(epoll_fd == -1) { perror("epoll_create1"); return EXIT_FAILURE; }

    int listen_fd = create_listen_socket(CPORT);
    if(listen_fd == -1) return EXIT_FAILURE;

    if(epoll_add(listen_fd, EPOLLIN | EPOLLET) == -1){
        perror("epoll_add listen_fd"); return EXIT_FAILURE;
    }

    exchange_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if(exchange_eventfd == -1) { perror("eventfd"); return EXIT_FAILURE; }

    if(epoll_add(exchange_eventfd, EPOLLIN | EPOLLET) == -1) {
        perror("epoll_add eventfd"); return EXIT_FAILURE;
    }
    event_loop(listen_fd);

    close(s1_fd);
    close(self_fd);
    close(epoll_fd);

    free(D);

    printf("Server shut down cleanly\n");
    return EXIT_SUCCESS;
}


