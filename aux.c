#include "aux.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sodium.h>
#include <pthread.h>
#include <time.h>

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#define PORT 8080
#define CPORT 8082

long min(long x, long y){
    if(x < y)
        return x;
    else return y;
}

void printboolvec(uint8_t* v, int len){
    int j = 0, k = 0;
    for(int i = 0; i < len; i++){
        if(k == 8){
            k = 0;
            j++;
        }
        printf("%d ", (v[j] >> k++) & 1);
    }
    printf("\n");

}

uint8_t reversebyte(uint8_t byte){
    uint8_t acc = 0;
    for(int i = 0; i < 8; i++)
        acc += (byte >> i & 1) << (7 - i);
    return acc;
}

void printbyte(uint8_t byte){
    for(int i = 0; i < 8; i++)
        printf("%d", byte >> i & 1);
    printf("\n");
}

void printvec(int* v, int len){
    for(int i = 0; i < len; i++)
        printf("%d ", v[i]);
    printf("\n");
}

int tobytes(int no_bits){
    return ceil(no_bits / 8.0);
}

int bitsize(int x){
    return ceil(log2(x));
}

//finite field conversion, (%) operator doesn't deal with negatives properly
int FF_convert(uint64_t x, uint64_t FF){
	if(x >= 0) return x % FF;
	else return ((x % FF) + FF) % FF;
}

void random_bool_vector(bool* v, int l){
    char buffer[32];
    int r, k = 0;
    for(int i = 0; i < l; i++){
        k %= 256;
        if(k == 0){     //generate a new random number every 256 bits
            randombytes_buf(buffer, 32);
            //random number of suitable length
            r = randombytes_uniform((int)pow(2, 256));
        }
        v[i] = (r >> k++) & 1;
    }
}

//create random vector v of length l where each coordinate is an element of GF(FF)
void random_vector(uint32_t* v, int l, uint32_t FF){
    uint32_t maxinclusive = FF - 1;
    int x = 1, y = 0;
    int byte = 0, bit = 0;
    bool nextbit;
    char* buffer = malloc(4 * l);
    if(!buffer){
        printf("could not allocate buffer in random_vector()\n");
        return;
    }
    randombytes_buf(buffer, 4 * l);
    for(int i = 0; i < l; i++){
        x = 1, y = 0;
        while(true){
            if(bit > 7){
                bit = 0;
                byte++;
            }
            x *= 2;
            nextbit = (buffer[byte] >> bit++) & 1;
            y = (y * 2) + nextbit;
            if(x > maxinclusive){
                if(y <= maxinclusive){
                    v[i] = y;
                    break;
                }
                x = x - maxinclusive - 1;
                y = y - maxinclusive - 1;
            }
        }
    }
    free(buffer);
}

int vector_to_int(bool* v, int len){
    int acc = 0;
    for(int i = 0; i < len; i++)
        acc += v[i] * (int)pow(2, i);
    return acc;
}

void int_to_vector(int x, bool* v, int maxlen){
    int j = 0;
    for(int i = maxlen - 1; i >= 0; i--)
        v[i] = (x >> j++) & 1;
}

void powset(int size, bool(*ret)[size], int expon){
    for(int i = 0; i < expon; i++)
        int_to_vector(i + 1, ret[i], size);
}


uint32_t aggregate_1D(uint32_t* array, int FF_size, int len){
    uint32_t acc = 0;
    for(int i = 0; i < len; i++){
        acc += array[i];
        acc %= FF_size;
    }
    return acc;
}

void secret_share(bool* v, bool* v1, bool* v2, int query_len){
    char buffer[32];
    uint32_t r;
    int k = 0;

    for(int i = 0; i < query_len; i++){
        k %= 32;
        if(k == 0){
            randombytes_buf(buffer, 32);
            r = randombytes_uniform((int)pow(2, 32));
        }
        v1[i] = (r  >> k++) & 1;
        v2[i] = v1[i] ^ v[i];
    }
}

//converts an integer index to a suitable (byte, bit) pair index, e.g. 9 -> (1, 1)
void indextobyteandbit(int *out_byte, int *out_bit, int x){
    *out_byte = x / 8;
    *out_bit = x % 8;
}

//converts an array of booleans to an array of corresponding bytes
void boolstobytes(uint8_t *out_bytes, bool *bools, int nobools){
    int nobytes = tobytes(nobools);
    memset(out_bytes, 0, nobytes);
    int bit = 0, byte = 0;
    for(int i = 0; i < nobools; i++){
        if(bit > 7){
            bit = 0;
            byte++;
        }
        out_bytes[byte] |= bools[i] << bit++;
    }
}

//converts an array of bytes to an array of corresponding booleans
void bytestobools(bool *out_bools, uint8_t *bytes, int nobools){
    int nobytes = tobytes(nobools);
    int bit = 0, byte = 0;
    for(int i = 0; i < nobools; i++){
        if(bit > 7){
            bit = 0;
            byte++;
        }
        out_bools[i] = bytes[byte] >> bit++ & 1;
    }
}

/*converts a bitstring (semantically, a boolean vector of characteristics)
 * to a vector of indices indicating which bits = 1*/
int bchartoindexvec(int *out_indexvec, uint8_t *bchars, int len){
    int byte = 0, bit = 0;
    int j = 0;
    for(int i = 0; i < len; i++){
        if(bit > 7){
            bit = 0;
            byte++;
        }
        if(bchars[byte] >> bit++ & 1){
            out_indexvec[j] = j;
            j++;
        }
    }
    return j;
}

/*converts a bitstring (semantically, a boolean vector of characteristics)
 * to a vector of indices indicating which bits = 1*/
void indexvectobchar(uint8_t *out_bchars, int *indexvec, int bchars_len, int indexvec_len){
    memset(out_bchars, 0, tobytes(bchars_len));
    int bit, byte, temp;
    for(int i = 0; i < indexvec_len; i++){
        indextobyteandbit(&byte, &bit, indexvec[i]);
        out_bchars[byte] |= 1 << bit;
    }
}

/* Write len bytes from buf to fd.
 * Returns 0 on success, -1 on syscall error, -2 on unexpected EOF. */
int send_all(int fd, const void *buf, size_t len){
    const uint8_t *ptr = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t sent = send(fd, ptr, len, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (sent == 0) return -2;
        ptr += sent;
        len -= (size_t)sent;
    }
    return 0;
}

/* Read exactly `len` bytes from `fd` into `buf`.
 * Returns 0 on success, -1 on syscall error, -2 on unexpected EOF. */
int recv_all(int fd, void *buf, size_t len){
    uint8_t *ptr = (uint8_t *)buf;
    while (len > 0) {
        ssize_t got = recv(fd, ptr, len, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (got == 0) return -2;
        ptr += got;
        len -= (size_t)got;
    }
    return 0;
}

/* Encode a uint64_t in network byte order (big-endian) into 8 bytes. */
void encode_uint64_be(uint8_t out[8], uint64_t val){
    out[0] = (uint8_t)(val >> 56);
    out[1] = (uint8_t)(val >> 48);
    out[2] = (uint8_t)(val >> 40);
    out[3] = (uint8_t)(val >> 32);
    out[4] = (uint8_t)(val >> 24);
    out[5] = (uint8_t)(val >> 16);
    out[6] = (uint8_t)(val >>  8);
    out[7] = (uint8_t)(val      );
}

/* Decode a uint64_t from 8 big-endian bytes. */
uint64_t decode_uint64_be(const uint8_t in[8])
{
    return  ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
          | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
          | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
          | ((uint64_t)in[6] <<  8) |  (uint64_t)in[7];
}

/* ------------------------------------------------------------------ */
/* send_uint32_array                                                    */
/* ------------------------------------------------------------------ */

/* Wire format:
 *   [ 8 bytes: element count, big-endian uint64_t ]
 *   [ count * 4 bytes: elements, each as big-endian uint32_t ]
 *
 * Socket buffer tuning: for large arrays consider calling setsockopt()
 * with SO_SNDBUF / SO_RCVBUF (e.g. 4 MB) before transferring.
 *
 * Returns 0 on success, -1 on syscall error, -2 on unexpected EOF. */
int send_uint32_array(int fd, const uint32_t *arr, uint64_t count, int send_batch_size){
    /* 1. Send the 8-byte big-endian element count. */
    uint8_t count_buf[8];
    encode_uint64_be(count_buf, count);
    int rc = send_all(fd, count_buf, sizeof(count_buf));

    if(rc != 0) return rc;
    if(count == 0) return 0;

    /* 2. Convert and send in batches to keep stack usage constant. */
    uint32_t batch_buf[send_batch_size]; /* matches BATCH_SIZE; declared here so
                                the size is visible at the allocation site */
    uint64_t remaining = count;
    const uint32_t *src = arr;

    while(remaining > 0){
        uint32_t chunk = (remaining < send_batch_size)? (uint32_t)remaining: send_batch_size;
        for(uint32_t i = 0; i < chunk; i++)
            batch_buf[i] = htonl(src[i]);
        rc = send_all(fd, batch_buf, chunk * sizeof(uint32_t));
        if (rc != 0) return rc;
        src += chunk;
        remaining -= chunk;
    }
    return 0;
}

int send_uint8_array(int fd, const uint8_t *arr, uint64_t count, int send_batch_size){
    /* 1. Send the 8-byte big-endian element count. */
    uint8_t count_buf[8];
    encode_uint64_be(count_buf, count);
    int rc = send_all(fd, count_buf, sizeof(count_buf));

    if(rc != 0) return rc;
    if(count == 0) return 0;

    /* 2. Convert and send in batches to keep stack usage constant. */
    uint8_t batch_buf[send_batch_size]; /* matches BATCH_SIZE; declared here so
                                the size is visible at the allocation site */
    uint64_t remaining = count;
    const uint8_t *src = arr;

    while(remaining > 0){
        uint32_t chunk = (remaining < send_batch_size)? (uint32_t)remaining: send_batch_size;
        for (uint32_t i = 0; i < chunk; i++)
            batch_buf[i] = src[i];
        rc = send_all(fd, batch_buf, chunk * sizeof(uint8_t));
        if(rc != 0) return rc;
        src += chunk;
        remaining -= chunk;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* recv_uint32_array                                                    */
/* ------------------------------------------------------------------ */

/* Receives an array sent by send_uint32_array().
 *
 * On success, *out_arr points to a heap-allocated buffer the caller must
 * free(), and *out_count holds the number of elements.
 * On failure, *out_arr is NULL and *out_count is 0.
 *
 * Returns:
 *   0    success
 *   -1   recv() syscall failed
 *   -2   peer closed connection mid-receive
 *   -3   count is zero or exceeds MAX_ARRAY_ELEMENTS
 *   -4   malloc() failed */
int recv_uint32_array(int fd, uint32_t **out_arr, uint64_t *out_count, int max_arr_elements){
    *out_arr = NULL;
    *out_count = 0;

    /* 1. Read the 8-byte big-endian element count. */
    uint8_t count_buf[8];
    int rc = recv_all(fd, count_buf, sizeof(count_buf));
    if(rc != 0) return rc;

    uint64_t count = decode_uint64_be(count_buf);

    if(count == 0 || count > max_arr_elements) return -3;

    /* 2. Allocate the output buffer. */
    uint32_t *arr = malloc(count * sizeof(uint32_t));
    if(!arr){
        errno = ENOMEM;
        return -4;
    }

    /* 3. Receive the raw big-endian payload directly into the buffer. */
    rc = recv_all(fd, arr, count * sizeof(uint32_t));
    if(rc != 0){
        free(arr);
        return rc;
    }

    /* 4. Convert from network byte order to host byte order in-place. */
    for (uint64_t i = 0; i < count; i++)
        arr[i] = ntohl(arr[i]);

    *out_arr = arr;
    *out_count = count;
    return 0;
}

int recv_uint8_array(int fd, uint8_t **out_arr, uint64_t *out_count, int max_arr_elements){
    *out_arr = NULL;
    *out_count = 0;

    /* 1. Read the 8-byte big-endian element count. */
    uint8_t count_buf[8];
    int rc = recv_all(fd, count_buf, sizeof(count_buf));
    if(rc != 0) return rc;

    uint64_t count = decode_uint64_be(count_buf);
    //printf("count = %" PRIu64 "\n", count);

    if(count == 0 || count > max_arr_elements) return -3;

    /* 2. Allocate the output buffer. */
    uint8_t *arr = malloc(count);
    if (!arr) {
        errno = ENOMEM;
        return -4;
    }

    /* 3. Receive the raw big-endian payload directly into the buffer. */
    rc = recv_all(fd, arr, count);
    if (rc != 0){
        free(arr);
        return rc;
    }

    *out_arr = arr;
    *out_count = count;
    return 0;
}
