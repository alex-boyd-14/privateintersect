#include "aux.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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
#define S1PORT 8081
#define S2PORT 8082
#define M_DEFAULT 4
#define L_DEFAULT 4
#define MAX_ARRAY_ELEMENTS 4096
#define SEND_BATCH_SIZE 256
const static char* target_addr = "127.0.0.1";
volatile static bool running;
const static bool benchmarking = false;
static int s1_fd, s2_fd;
static int m, L, line;

//connect to server s
int connect_serv(bool s){
    int status, serv_fd;
    struct sockaddr_in serv_addr;
    if ((serv_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    if(s) serv_addr.sin_port = htons(S2PORT);
    else serv_addr.sin_port = htons(S1PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, target_addr, &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    fprintf(stderr, "Attempting to connect...\n");
    if ((status = connect(serv_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    printf("connected to server %d, fd = %d\n", s + 1, serv_fd);
    return serv_fd;
}

static int recv_hello(){
    uint8_t buf[2];
    int rc = recv_all(s1_fd, buf, sizeof(buf));
    if (rc != 0) return rc;
    m = buf[0];
    L = buf[1];
    line = m * L;
    return 0;
}

static int recv_query_response(){
    uint8_t buf[1];
    int rc = recv_all(s1_fd, buf, sizeof(buf));
    if (rc != 0) return rc;
    return buf[0];
}

void client_shutdown(int s1_fd, int s2_fd){
    fprintf(stderr, "Shutting down...\n");
    shutdown(s1_fd, SHUT_WR);
    shutdown(s2_fd, SHUT_WR);
    close(s1_fd);
    close(s2_fd);
    uint8_t drain_buf[4096];
    while(recv(s1_fd, drain_buf, sizeof(drain_buf), 0) > 0){}
    while(recv(s2_fd, drain_buf, sizeof(drain_buf), 0) > 0){}
    running = false;
}

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
    fprintf(stderr, "recv array returned: %d\n", rc);

    if(rc == 0){
        printf("received %" PRIu64 " elements\n", count);
    }
    else if (rc == -1){
        fprintf(stderr, "recv failed: syscall error: %s\n", strerror(errno));
        return -1;
    }
    else if (rc == -2){
        fprintf(stderr, "recv failed: server closed connection unexpectedly\n");
        return -1;
    }
    else{
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
    printf("fd = %d\n", target_fd);
    int rc = recv_uint32_array(target_fd, &arr, &count, MAX_ARRAY_ELEMENTS);
    fprintf(stderr, "recv array returned: %d\n", rc);
    printf("hellorecv32\n");
    if(rc == 0){
        printf("received %" PRIu64 " elements\n", count);
    }
    else if (rc == -1){
        fprintf(stderr, "recv failed: syscall error: %s\n", strerror(errno));
        return -1;
    }
    else if (rc == -2){
        fprintf(stderr, "recv failed: server closed connection unexpectedly\n");
        return -1;
    }
    else{
        fprintf(stderr, "recv failed: rc=%d\n", rc);
        return -1;
    }
    *out_arr = arr;
    *out_count = count;
    return 0;
}

int post_data(int s1_fd, int s2_fd){
	char readBuf[256];
    printf("Please enter your data as a bitstring of length %d * %d\n", m, L);

	if(fgets(readBuf, sizeof(readBuf), stdin) == NULL){
		printf("error during fgets()\n");
		return -1;
	}
	
	bool d[line];
	
	if(!strncmp(readBuf, "all", 3)){
        for(int i = 0; i < line; i++)
            d[i] = 0;
    }
    else{
        int num;
        if(line > 256){
            printf("readBuf[] not large enough\n");
            return -1;

        }
        for(int i = 0; i < line; i++){
            num = readBuf[i] - '0';
   			if(num != 0 && num != 1){
                fprintf(stderr, "error: please enter a bitstring of your data\n");
                printf("num = %d\n", num);
                return -1;
            }
            d[i] = num;
        }
    }
	bool d1[line], d2[line];
    secret_share(d, d1, d2, line);

    int msg_len = 1 + tobytes(line);

    uint8_t s1_send_buf[msg_len];
    uint8_t s2_send_buf[msg_len];
    s1_send_buf[0] = 0;
    s2_send_buf[0] = 0;
    boolstobytes(&s1_send_buf[1], d1, line);
    boolstobytes(&s2_send_buf[1], d2, line);


    if (send_8(s1_fd, s1_send_buf, msg_len) != 0)
        perror("send to s1 failed");
    if (send_8(s2_fd, s2_send_buf, msg_len) != 0)
        perror("send to s2 failed");
    printf("data posted\n");
    return 0;
}

int query_data(){
    char readBuf[256];
	printf("Which attributes do you wish to include? Please enter comma-seperated integers or type 'all'\n");

	if(fgets(readBuf, sizeof(readBuf), stdin) == NULL){
		printf("error during fgets()\n");
		return -1;
	}

	int intersection_indices[m];
	int index_len = 0;
    int query_len = 0;
    int query_len_bytes = 0;

	char *endptr, *startptr;
   	long int num;

	if(!strncmp(readBuf, "all", 3)){
		index_len = m;
        query_len = line;
		for(int i = 0; i < m; i++)
			intersection_indices[i] = i;
	}
   	else{
		startptr = readBuf;
		for(int i = 0; i < m; i++){
   			num = strtol(startptr, &endptr, 10);
   			if(*endptr == ','){
				if(num < 1){
					printf("please enter a positive integer\n");
					return 1;
				}
                if(num > m){
                    printf("index out of bounds, m = %d\n", m);
                    return 1;
                }
				if(num < 10) startptr += 2;	//faster than calculating log, will realistically not need more than 10
				else if(num < 100) startptr += 3;
				else if(num < 1000) startptr += 4;
				else{
					printf("please enter a number below 1000\n");
					return 1;
				}
                intersection_indices[i] = num - 1;
  			}
			else if(*endptr == '\0' || *endptr == '\n' || *endptr == ' '){
				if(num < 1){
					printf("please enter a positive integer\n");
					return 1;
				}
                if(num > m){
                    printf("index out of bounds, m = %d\n", m);
                    return 1;
                }
				if(num >= 1000){
					printf("please enter a number below 1000\n");
					return 1;
				}
				intersection_indices[i] = num - 1;
   				index_len = i + 1;
                query_len = index_len * L;
                query_len_bytes = tobytes(query_len);
				break;
			}
            else{
				printf("bad character %c\n", *endptr);
				return 1;
			}
		}
	}
	if(index_len == 0){
		printf("please provide an attribute\n");
		return 1;
	}

    bool query[query_len], q1[query_len], q2[query_len];
    if(benchmarking)
        for(int i = 0; i < query_len; i++)
            query[i] = 0;
    else{
        char readBuf2[256];
        printf("Please enter your data under the specified attributes you just gave, as a bitstring\n");
        if(fgets(readBuf2, sizeof(readBuf2), stdin) == NULL){
			printf("error during fgets()\n");
			return -1;
		}

        if(!strncmp(readBuf2, "all", 3)){
            for(int i = 0; i < query_len; i++)
                query[i] = 0;
        }
        else{
            startptr = readBuf2;
            num = strtol(startptr, &endptr, 2);
            if(*endptr != '\0' && *endptr != '\n' && *endptr != ' '){
                printf("please enter a bitstring with no spaces\n");
                return 1;
            }
            if(endptr - startptr != query_len){
                printf("query vector must be of length %d, yours is %ld\n", query_len, endptr - startptr);
                return 1;
            }
            char temp;
            for(int i = 0; i < query_len; i++){
                temp = readBuf2[i];
                query[i] = atoi(&temp);
            }
        }
    }

    secret_share(query, q1, q2, query_len);
    int msg_len = 1 + 8 + query_len_bytes;

    uint8_t s1_send_buf[msg_len];
    uint8_t s2_send_buf[msg_len];
    s1_send_buf[0] = 1;
    s2_send_buf[0] = 1;
    indexvectobchar(&s1_send_buf[1], intersection_indices, 64, index_len);
    indexvectobchar(&s2_send_buf[1], intersection_indices, 64, index_len);
    boolstobytes(&s1_send_buf[1 + 8], q1, query_len);
    boolstobytes(&s2_send_buf[1 + 8], q2, query_len);


    if (send_8(s1_fd, s1_send_buf, msg_len) != 0)
        perror("send to s1 failed");
    if (send_8(s2_fd, s2_send_buf, msg_len) != 0)
        perror("send to s2 failed");
    printf("query sent to servers\n");
    bool result = recv_query_response();
    if(result)
        printf("you are vulnerable\n");
    else printf("you are not vulnerable\n");
}

int main(int argc, char* argv[]){
    m = M_DEFAULT, L = L_DEFAULT, line = m * L;
    s1_fd = connect_serv(0);
    if(s1_fd == -1) return -1;
    if(recv_hello() < 0)
        printf("error receiving server hello, setting defaults for m and L\n");
    else printf("finished server hello\n");
    s2_fd = connect_serv(1);
    if(s2_fd == -1) return -1;
    running = true;

	while(running){
        //printf("running = %d\n", running);
        char readBuf[256];
        printf("Enter 1 to post data, 2 to make query, or 0 to close connection\n");
        if(fgets(readBuf, sizeof(readBuf), stdin) == NULL){
            printf("error during fgets()\n");
            return -1;
        }
        if(!strncmp(readBuf, "1", 1)) post_data(s1_fd, s2_fd);
        else if(!strncmp(readBuf, "2", 1)) query_data(s1_fd, s2_fd);
        else if(!strncmp(readBuf, "0", 1)) client_shutdown(s1_fd, s2_fd);
        else { printf("please enter either 0, 1, or 2\n"); return 1;}
    }
    return 0;
}
