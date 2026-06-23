#ifndef AUX_H
#define AUX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

long min(long x, long y);
void printboolvec(uint8_t* v, int len);
uint8_t reversebyte(uint8_t byte);
void printbyte(uint8_t byte);
void printvec(int* v, int len);
int tobytes(int no_bits);
int bitsize(int x);
int FF_convert(uint64_t x, uint64_t FF);
void random_bool_vector(bool* v, int l);
void random_vector(uint32_t* v, int l, uint32_t FF);
int vector_to_int(bool* v, int len);
void int_to_vector(int x, bool* v, int maxlen);
void powset(int size, bool(*ret)[size], int expon);
uint32_t aggregate_1D(uint32_t* array, int FF_size, int len);
void secret_share(bool* v, bool* v1, bool* v2, int query_len);
void indextobyteandbit(int *out_byte, int *out_bit, int x);
void boolstobytes(uint8_t *out_bytes, bool *bools, int nobools);
void bytestobools(bool *out_bools, uint8_t *bytes, int nobools);
int bchartoindexvec(int *out_indexvec, uint8_t *bchars, int len);
void indexvectobchar(uint8_t *out_bchars, int *indexvec, int bchars_len, int indexvec_len);
int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);
void encode_uint64_be(uint8_t out[8], uint64_t val);
uint64_t decode_uint64_be(const uint8_t in[8]);
int send_uint32_array(int fd, const uint32_t *arr, uint64_t count, int send_batch_size);
int send_uint8_array(int fd, const uint8_t *arr, uint64_t count, int send_batch_size);
int recv_uint32_array(int fd, uint32_t **out_arr, uint64_t *out_count, int max_arr_elements);
int recv_uint8_array(int fd, uint8_t **out_arr, uint64_t *out_count, int max_arr_elements);

#endif
