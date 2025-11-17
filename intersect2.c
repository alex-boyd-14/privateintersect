#include "libote_wrap.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <sodium.h>
#include <pthread.h>
#include <time.h>

bool verbose;
int n, m, L, line, FF_size; //n = number of records, m = number of attributes, L = bitlength per attribute, line = record bitlength
double artificial_delay = 0., RTT = 0.05; //50ms delay to send data

void servers_communicate(){
    artificial_delay += RTT;
}

void print_records(bool (*records)[line], int total_bits){
    for(int i = 0; i < n; i++){
        for(int j = 0; j < line; j++){
            if(j == 0)
                printf("(%d", records[i][j]);
            else if(j == line - 1)
                printf("%d)\n", records[i][j]);
            else if(j % L == L - 1)
                printf("%d|", records[i][j]);
            else printf("%d", records[i][j]);
        }
    }
    printf("\n");
}

void printboolvec(bool* v, int len){
    for(int i = 0; i < len; i++)
        printf("%d ", v[i]);
    printf("\n");
}


void printvec(int* v, int len){
    for(int i = 0; i < len; i++)
        printf("%d ", v[i]);
    printf("\n");
}

struct dabit{
	int b;
	int a;
};

int OT(int m1, int m2, bool choice){
    if(choice)
        return m2;
    else return m1;
}

//finite field conversion, (%) operator close but doesn't deal with negatives properly
int FF_convert(int x, int FF){
	if(x >= 0) return x % FF;
	else return (x % FF) + FF;
}

//create random vector v of length l where each coordinate is an element of GF(FF)
void random_vector(int* v, int l, int FF){
    char buffer[32];
    for(int i = 0; i < l; i++){
        randombytes_buf(buffer, 32);
        v[i] = randombytes_uniform(FF);
    }
}

int vector_to_int(int* v, int len){
    int acc = 0;
    for(int i = 0; i < len; i++)
        acc += v[i] * (int)pow(2, i);
    return acc;
}

void int_to_vector(int x, int* v, int maxlen){
    int j = 0;
    for(int i = maxlen - 1; i >= 0; i--)
        v[i] = (x >> j++) & 1;
}

void powset(int rsize, int(*ret)[rsize]){
    int len = (int)pow(2, rsize) - 2;
    for(int i = 0; i < len; i++)
        int_to_vector(i + 1, ret[i], rsize);
}

void bitwiseXOR(int* v1, int* v2, int* ret, int len){
    for(int i = 0; i < len; i++)
        ret[i] =  v1[i] ^ v2[i];
}

void* OTeSendThread(void* arg){
    void** unpack = (void**)arg;
    uint16_t* messages1 = (uint16_t*)unpack[0];
    uint16_t* messages2 = (uint16_t*)unpack[1];
    int size = *(int*)unpack[2];
    OTeSend(messages1, messages2, size);
    return NULL;
}

//D_i is each server's boolean share of the record data, I_i is the computed intersection shares
void intersect(int l, bool (*V1)[l], bool (*V2)[l], bool * T1, bool* T2, bool* Z1, bool* Z2){
   
    int no_rounds = (int)ceil(log2(l));
   
    int j = 0;
    int jcheckpoint;
    int index1, index2, spacing;
    int no_pairs = l;
    bool D1_buf[n], D2_buf[n], E1_buf[n], E2_buf[n], D[n], E[n]; //buffers for d1, d2,... values
    for(int round = 0; round < no_rounds; round++){
        no_pairs = l / 2; //e.g. if we have 7 indices, we have 3 pairs and 1 leftover
        l -= no_pairs;
        spacing = (int)pow(2, round);
        for(int pair = 0; pair < no_pairs; pair++){
            index1 = 2*pair*spacing; //first index of the pair
            index2 = spacing*(2*pair + 1); //second index of the pair
            jcheckpoint = j;
            for(int i = 0; i < n; i++){
                //server 1 computes intermediate values d1 = x1 - a1
                D1_buf[i] = V1[i][index1] ^ T1[j];
                //e1 = y1 - b1
                E1_buf[i] = V1[i][index2] ^ T1[j + 1];

                //server 2 does similarly
                D2_buf[i] = V2[i][index1] ^ T2[j];
                E2_buf[i] = V2[i][index2] ^ T2[j + 1];
                j += 3;
            }
            j = jcheckpoint;
            servers_communicate();
            //servers publish shares, i.e. server 1 sends D1_buf and E1_buf, server 2 similarly
            for(int i = 0; i < n; i++){
                //now we assume both servers have all parts to reconstruct D and E, and thus both calculate:
                D[i] = D1_buf[i] ^ D2_buf[i];
                E[i] = E1_buf[i] ^ E2_buf[i];
                //server 1 computes z1 as d*b1 + e*a1 + c1 and stores it in intermediate array I
                V1[i][index1] = D[i]*T1[j + 1] ^ E[i]*T1[j] ^ T1[j + 2];
                //server 2 computes z2 as d*e + d*b2 + e*a2 + c2
                V2[i][index1] = D[i]*E[i] ^ D[i]*T2[j + 1] ^ E[i]*T2[j] ^ T2[j + 2];
                j += 3;
            }
        }
    }
    //finish by setting the return arrays Z to the first index of the intermediate array
    for(int i = 0; i < n; i++){
        Z1[i] = V1[i][0];
        Z2[i] = V2[i][0];
    }
}

void cout_size_reduction(int* R, int* S, int* A, uint16_t* msgs1, uint16_t* msgs2, uint16_t* choices, int j, int* counter){
    random_vector(R, j, 2);
    random_vector(A, j, j + 1);
    random_vector(S, j, 2);
    for(int i = 0; i < j; i++){
        msgs1[*counter] = FF_convert(R[i] - A[i], j + 1);
        msgs2[*counter] = FF_convert(1 - A[i] - R[i], j + 1);
        choices[*counter] = S[i];
        (*counter)++;
    }
}

void cout_product_sharing(int* r, int* s, int* a, uint16_t* msgs1, uint16_t* msgs2, uint16_t* choices, int exp, int* counter){
    random_vector(r, exp, 2);
    random_vector(a, exp, 2);
    random_vector(s, exp, 2);
    for(int i = 0; i < exp; i++){
        msgs1[*counter] = a[i];
        msgs2[*counter] = a[i] ^ r[i];
        choices[*counter] = s[i];
        (*counter)++;
    }
}

void couteauPrepLight(int batch_size, int depth, int l, int exp, int (*R)[depth][l], int (*S)[depth][l], int (*A)[depth][l], int (*B)[depth][l], int rsize, int totalOTs, int* js){
    int i, counter = 0;
    uint16_t* msgs1 = malloc(sizeof(uint16_t) * totalOTs), *msgs2 = malloc(sizeof(uint16_t) * totalOTs), *choices = malloc(sizeof(uint16_t) * totalOTs);
    if(!msgs1 || !msgs2 || !choices){
        printf("error allocating space (couteauPrep())\n");
        return;
    }
    
    for(int ii = 0; ii < batch_size; ii++)
        for(i = 0; i < depth; i++)
            cout_size_reduction(R[ii][i], S[ii][i], A[ii][i], msgs1, msgs2, choices, js[i], &counter);
    
    if(depth == 0)
        return;
    
    void* arg[3];
    arg[0] = msgs1;
    arg[1] = msgs2;
    arg[2] = &totalOTs;
    //uint8_t output[8 * totalOTs];
    uint8_t* output = malloc(sizeof(uint8_t) * totalOTs * 8);
    if(!output){
        printf("error allocating space (couteauPrep())\n");
        return;
    }
    pthread_t send_thread;
    pthread_create(&send_thread, NULL, OTeSendThread, arg);
    OTeRecv(output, choices, totalOTs);
    pthread_join(send_thread, NULL);
    servers_communicate();
    
    int k = 0;
    for(int ii = 0; ii < batch_size; ii++)
        for(i = 0; i < depth; i++)
            for(int jj = 0; jj < js[i]; jj++)
                B[ii][i][jj] = (int)output[8 * k++];
    free(output);
}

void couteauETLight(int depth, int l, int exp, bool (*V1)[l], bool (*V2)[l], bool* T1, bool* T2, bool* Z1, bool* Z2, int (*R)[depth][l], int (*S)[depth][l], int (*A)[depth][l], int (*B)[depth][l], int rsize, int* js){
    int (*xs)[depth + 1][l] = malloc(sizeof(int) * n * (depth + 1) * l), (*ys)[depth + 1][l] = malloc(sizeof(int) * n * (depth + 1) * l);
    if(!xs || !ys){
        printf("could not allocate\n");
        return;
    }
    
    //server1 sets x1 = x for every record
    for(int record = 0; record < n; record++)
        for(int ii = 0; ii < l; ii++)
            xs[record][0][ii] = V1[record][ii];
    //server2 sets y1 = y for every record
    for(int record = 0; record < n; record++)
        for(int ii = 0; ii < l; ii++)
            ys[record][0][ii] = V2[record][ii];
    
    int i, acc1, acc2;
   
    for(i = 0; i < depth; i++){
        int (*temp1)[js[i]] = malloc(sizeof(int) * n * js[i]), (*temp2)[js[i]] = malloc(sizeof(int) * n * js[i]), (*z)[js[i]] = malloc(sizeof(int) * n * js[i]);
        if(!temp1 || !temp2 || !z){
            printf("could not allocate\n");
            return;
        }
        //server1 sends for each record: temp1 = r[i] ^ x[i];
        for(int record = 0; record < n; record++)
            bitwiseXOR(R[record][i], xs[record][i], temp1[record], js[i]);
        //server2 sends for each record: temp2 = s[i] ^ y[i];
        for(int record = 0; record < n; record++)
            bitwiseXOR(S[record][i], ys[record][i], temp2[record], js[i]);
        
        //servers exchange temp1 and temp2
        servers_communicate();
        //and calculate z as z = temp1 ^ temp2
        for(int record = 0; record < n; record++)
            bitwiseXOR(temp1[record], temp2[record], z[record], js[i]);
    
        //server1 calculates what will become xs[i+1]
        for(int record = 0; record < n; record++){
            acc1 = 0;
            for(int ii = 0; ii < js[i]; ii++)
                acc1 += (int)pow(-1, z[record][ii]) * A[record][i][ii];
            acc1 = FF_convert(-acc1, js[i] + 1);
            int_to_vector(acc1, xs[record][i + 1], js[i + 1]);
        }
        
        //server2 calculates what will become ys[i + 1]
        for(int record = 0; record < n; record++){
            acc2 = 0;
            for(int ii = 0; ii < js[i]; ii++)
                acc2 += (int)pow(-1, z[record][ii]) * B[record][i][ii] + z[record][ii];
            acc2 = FF_convert(acc2, js[i] + 1);
            int_to_vector(acc2, ys[record][i + 1], js[i + 1]);
        }
        free(temp1);
        free(temp2);
        free(z);
    }
    bool I1[n][js[depth]], I2[n][js[depth]];
    for(int record = 0; record < n; record++){
        for(int jj = 0; jj < js[depth]; jj++){
            I1[record][jj] = xs[record][depth][jj];
            I2[record][jj] = ys[record][depth][jj] ^ 1;
        }
    }
    free(xs);
    free(ys);
    intersect(js[depth], I1, I2, T1, T2, Z1, Z2);
}
    

void couteauPrep(int batch_size, int depth, int l, int exp, int (*R)[depth][l], int (*S)[depth][l], int (*A)[depth][l], int (*B)[depth][l], int (*r)[exp], int (*s)[exp], int (*a)[exp], int (*b)[exp], int rsize, int noOTs_SR, int* js){
    int i, counter = 0, noOTs_PS = batch_size * exp, totalOTs = noOTs_PS + noOTs_SR;
    uint16_t* msgs1 = malloc(sizeof(uint16_t) * totalOTs), *msgs2 = malloc(sizeof(uint16_t) * totalOTs), *choices = malloc(sizeof(uint16_t) * totalOTs);
    if(!msgs1 || !msgs2 || !choices){
        printf("error allocating space (couteauPrep())\n");
        return;
    }
    for(int ii = 0; ii < batch_size; ii++)
        for(i = 0; i < depth; i++)
            cout_size_reduction(R[ii][i], S[ii][i], A[ii][i], msgs1, msgs2, choices, js[i], &counter);
    
    for(int ii = 0; ii < batch_size; ii++)
        cout_product_sharing(r[ii], s[ii], a[ii], msgs1, msgs2, choices, exp, &counter);
    
    void* arg[3];
    arg[0] = msgs1;
    arg[1] = msgs2;
    arg[2] = &totalOTs;
    //uint8_t output[8 * totalOTs];
    uint8_t* output = malloc(sizeof(uint8_t) * totalOTs * 8);
    pthread_t send_thread;
    if(!output){
        printf("error allocating space (couteauPrep())\n");
        return;
    }
    
    pthread_create(&send_thread, NULL, OTeSendThread, arg);
    OTeRecv(output, choices, totalOTs);
    pthread_join(send_thread, NULL);
    servers_communicate();
    int k = 0;
    for(int ii = 0; ii < batch_size; ii++)
        for(i = 0; i < depth; i++)
            for(int jj = 0; jj < js[i]; jj++)
                B[ii][i][jj] = (int)output[8 * k++];
    
    for(int ii = 0; ii < batch_size; ii++)
        for(int jj = 0; jj < exp; jj++)
            b[ii][jj] = (int)output[8 * k++];
    
    free(output);
    free(msgs1);
    free(msgs2);
    free(choices);
}


//rsize is the reduction size
void couteauET(int depth, int l, int exp, bool (*V1)[l], bool (*V2)[l], bool* Z1, bool* Z2, int (*R)[depth][l], int (*S)[depth][l], int (*A)[depth][l], int (*B)[depth][l], int (*r)[exp], int (*s)[exp], int (*a)[exp], int (*b)[exp], int rsize, int* js){
    
    int (*xs)[depth + 1][l] = malloc(sizeof(int) * n * (depth + 1) * l), (*ys)[depth + 1][l] = malloc(sizeof(int) * n * (depth + 1) * l);
    if(!xs || !ys){
        printf("could not allocate\n");
        return;
    }
    
    //server1 sets x1 = x for every record
    for(int record = 0; record < n; record++)
        for(int ii = 0; ii < l; ii++)
            xs[record][0][ii] = V1[record][ii];
    //server2 sets y1 = y for every record
    for(int record = 0; record < n; record++)
        for(int ii = 0; ii < l; ii++)
            ys[record][0][ii] = V2[record][ii];
    
    int i, acc1, acc2;
   
    for(i = 0; i < depth; i++){
        int (*temp1)[js[i]] = malloc(sizeof(int) * n * js[i]), (*temp2)[js[i]] = malloc(sizeof(int) * n * js[i]), (*z)[js[i]] = malloc(sizeof(int) * n * js[i]);
        if(!temp1 || !temp2 || !z){
            printf("could not allocate\n");
            return;
        }
        //server1 sends for each record: temp1 = r[i] ^ x[i];
        for(int record = 0; record < n; record++)
            bitwiseXOR(R[record][i], xs[record][i], temp1[record], js[i]);
        //server2 sends for each record: temp2 = s[i] ^ y[i];
        for(int record = 0; record < n; record++)
            bitwiseXOR(S[record][i], ys[record][i], temp2[record], js[i]);
        
        //servers exchange temp1 and temp2
        servers_communicate();
        //and calculate z as z = temp1 ^ temp2
        for(int record = 0; record < n; record++)
            bitwiseXOR(temp1[record], temp2[record], z[record], js[i]);
    
        //server1 calculates what will become xs[i+1]
        for(int record = 0; record < n; record++){
            acc1 = 0;
            for(int ii = 0; ii < js[i]; ii++)
                acc1 += (int)pow(-1, z[record][ii]) * A[record][i][ii];
            acc1 = FF_convert(-acc1, js[i] + 1);
            int_to_vector(acc1, xs[record][i + 1], js[i + 1]);
        }
        
        //server2 calculates what will become ys[i + 1]
        for(int record = 0; record < n; record++){
            acc2 = 0;
            for(int ii = 0; ii < js[i]; ii++)
                acc2 += (int)pow(-1, z[record][ii]) * B[record][i][ii] + z[record][ii];
            acc2 = FF_convert(acc2, js[i] + 1);
            int_to_vector(acc2, ys[record][i + 1], js[i + 1]);
        }
        free(temp1);
        free(temp2);
        free(z);
    }
    
    
    int I[exp][rsize];
    powset(rsize, I);
    
    //server1
    int alpha[n], Alpha[n][exp], EX[n][exp];
    for(int record = 0; record < n; record++){
        for(int k = 0; k < exp; k++){
            acc1 = 1;
            for(int ii = 0; ii < rsize; ii++){
                if(I[k][ii])
                    acc1 *= 1 ^ xs[record][depth][ii];
            }
            EX[record][k] = acc1;
            Alpha[record][k] = r[record][k] ^ acc1;
        }
    }
    random_vector(alpha, n, 2);
    
    //server2
    int beta[n], Beta[n][exp];
    for(int record = 0; record < n; record++){
        for(int k = 0; k < exp; k++){
            acc2 = 1;
            for(int ii = 0; ii < rsize; ii++){
                if(!I[k][ii])
                    acc2 *= ys[record][depth][ii];
            }
            Beta[record][k] = s[record][k] ^ acc2;
        }
    }
    random_vector(beta, n, 2);

    servers_communicate();
    //servers send each other alpha and beta (+Alpha and Beta)
    
    //server1
    for(int record = 0; record < n; record++){
        acc1 = 0;
        acc2 = 1;
        for(int k = 0; k < exp; k++)
            acc1 += a[record][k] ^ (Beta[record][k] * EX[record][k]);
        acc1 %= 2;
        for(int ii = 0; ii < rsize; ii++)
            acc2 *= 1 ^ xs[record][depth][ii];
        Z1[record] = acc1 ^ acc2 ^ alpha[record] ^ beta[record];
    }
    
    //server2
    int acc3, acc4;
    for(int record = 0; record < n; record++){
        acc3 = 0;
        acc4 = 1;
        for(int k = 0; k < exp; k++)
            acc3 += b[record][k] ^ (Alpha[record][k] * s[record][k]);
        acc3 %= 2;
        for(int ii = 0; ii < rsize; ii++){
            acc4 *= ys[record][depth][ii];
        }
        Z2[record] = acc3 ^ acc4 ^ alpha[record] ^ beta[record];
    }
    free(xs);
    free(ys);
}

void secret_share(bool* v, bool* v1, bool* v2, int query_len){
    char buffer[32];
    uint32_t r;
    int k = 0;
    
    for(int i = 0; i < query_len; i++){
        k %= 256;
        if(k == 0){
            randombytes_buf(buffer, 32);
            r = randombytes_uniform((int)pow(2, 256));
        }
		v1[i] = (r  >> k++) & 1;
        v2[i] = v1[i] ^ v[i];
    }
}

//generate n records with L bits of information each
//s1_records is server 1's share of the record data, s2 likewise
/* the sodium library works by generating one
number from a given number of random bytes rather than
a random bitstring of given length. Therefore, in the
code below, an integer of suitable length is generated,
before being converted to binary. Each bit in the binary
representation becomes the record data.
*/
void generate_records(bool (*records)[line], bool (*s1_records)[line], bool (*s2_records)[line]){
    //int total_bits = n * line;
    char buffer[32];
    uint32_t r;
    //int j1 = total_bits - 1, j2 = (total_bits * 2) - 1;
    int k = 0;
    
    for(int i = 0; i < n; i++){
        for(int j = 0; j < line; j++){
            k %= 256;
            if(k < 2){     //generate a new random number every 256 bits
                randombytes_buf(buffer, 32);
                //random number of suitable length
                r = randombytes_uniform((int)pow(2, 256));
            }
            //jx is the bit to extract
            //extract the jth bit of binary rep. of r and set it to record data
            s1_records[i][j] = (r >> k++) & 1;
            //choose another random bit for first secret share
            s2_records[i][j] = (r >> k++) & 1;
            //set second share such that s2 = s1 XOR S
            records[i][j] = s1_records[i][j] ^ s2_records[i][j];
        }
    }
}

//dabitgen algorithm according to [1] but parallelised
void generate_dabits(struct dabit* s1_dabits, struct dabit* s2_dabits, int batch_size){
    int no_bytes = ceil(ceil(log2(FF_size)) / 8.0); //how many bytes required to store a number generated in the finite field
	//s1 chooses n random bits B1
	uint16_t B1[batch_size];
	char r1_buf[32];
    int k = 0;
    uint32_t r;
    for(int i = 0; i < batch_size; i++){
        k %= 256;
        if(k == 0){
            randombytes_buf(r1_buf, 32);
            r = randombytes_uniform((int)pow(2, 256));
        }
        B1[i] = (r >> k++) & 1;
    }

	//s1 chooses n random field elements X and sets y1 = -x mod p for each one 	
	uint16_t X[batch_size];
	uint16_t Y1[batch_size];
	
	char x_buf[32];	//32 byte max finite field size should be fine
	for(int i = 0; i < batch_size; i++){
		randombytes_buf(x_buf, 32);
		X[i] = randombytes_uniform(FF_size);
		Y1[i] = FF_convert(-X[i], FF_size);
	}

	//s2 chooses n random bits B2
	uint16_t B2[batch_size]; //choices
	char r2_buf[32];
    k = 0;
    for(int i = 0; i < batch_size; i++){
        k %= 256;
        if(k == 0){
            randombytes_buf(r2_buf, 32);
            r = randombytes_uniform((int)pow(2, 256));
        }
        B2[i] = (r >> k++) & 1;
    }
	//s1 acts as OT sender, sending (x, x + b1), s2 acts as receiver with choice bit b2
	uint16_t Y2[batch_size];
	uint8_t output[batch_size * 8];
	//for(int i = 0; i < batch_size; i++)
	//	Y2[i] = oblivious_transfer(X[i], FF_convert(X[i] + B1[i]), B2[i]);
	pthread_t thread2;
	uint16_t messages2[batch_size];
	for(int i = 0; i < batch_size; i++)
		messages2[i] = FF_convert(X[i] + B1[i], FF_size);
	void* arg[3];
	arg[0] = X; //messages1
	arg[1] = messages2;
	arg[2] = &batch_size;
	
	pthread_create(&thread2, NULL, OTeSendThread, arg);
	OTeRecv(output, B2, batch_size);
	pthread_join(thread2, NULL);
    servers_communicate();
	
    int j, acc;
    for(int i = 0; i < batch_size; i++){
        acc = 0;
        j = i * 8;
        for(int ii = 0; ii < no_bytes; ii++)
            acc += output[j + ii] << (8 * ii);
        Y2[i] = acc;
    }

	//both servers compute a_i = b_i - 2*y_i and output values
	uint16_t A1[batch_size];
	for(int i = 0; i < batch_size; i++){
		A1[i] = FF_convert(B1[i] - (2 * Y1[i]), FF_size);
		s1_dabits[i].b = B1[i];
		s1_dabits[i].a = A1[i];
	}

	uint16_t A2[batch_size];
	for(int i = 0; i < batch_size; i++){
		A2[i] = FF_convert(B2[i] - (2 * Y2[i]), FF_size);
		s2_dabits[i].b = B2[i];
		s2_dabits[i].a = A2[i];
	}
}

// pre-compute a batch of beaver triples in parallel
int generate_beaver_triples(bool* s1_triples, bool* s2_triples, int batch_size){
	
	//server 1 samples 'batch_size' bit doubles (a1, b2) plus 'batch_size' random bits R1 for the OTs
	char s1_buf[32];
    uint16_t* s1_R = malloc(sizeof(uint16_t) * batch_size);
    if(!s1_R){
        printf("could not allocate space\n");
        return -1;
    }
    
	//extract random data similar to generate_records()
	int k = 0, r, j;
	for(int i = 0; i < batch_size; i++){
        j = 3 * i;
        k %= 256;
        if(k < 3){
            randombytes_buf(s1_buf, 32);
            r = randombytes_uniform((int)pow(2, 256));
        }
		s1_triples[j] = (r >> k++) & 1;
		s1_triples[j + 1] = (r >> k++) & 1;
		s1_R[i] = (r >> k++) & 1;
	}
    
    char s2_buf[32];
    uint16_t* s2_R = malloc(sizeof(uint16_t) * batch_size);
    if(!s2_R){
        printf("could not allocate space\n");
        return -1;
    }

    
    //extract random data similar to generate_records()
    k = 0;
    for(int i = 0; i < batch_size; i++){
        j = 3 * i;
        k %= 256;
        if(k < 3){
            randombytes_buf(s2_buf, 32);
            r = randombytes_uniform((int)pow(2, 256));
        }
        s2_triples[j] = (r >> k++) & 1;
        s2_triples[j + 1] = (r >> k++) & 1;
        s2_R[i] = (r >> k++) & 1;
    }

	//perform 2 OTs
	pthread_t send_thread1, send_thread2;
	void* arg1[3], *arg2[3];
	arg1[0] = s1_R; //messages1 for first OT
	arg2[0] = s2_R;	//messages1 for second OT
    uint16_t* messages1 = malloc(sizeof(uint16_t) * batch_size), *messages2 = malloc(sizeof(uint16_t) * batch_size);
	//uint16_t messages1[batch_size], messages2[batch_size];
    if(!messages1 || !messages2){
        printf("could not allocate space\n");
        return -1;
    }
	for(int i = 0; i < batch_size; i++){
        j = 3 * i;
		messages1[i] = s1_R[i] ^ s1_triples[j];	//messages2 for first OT
		messages2[i] = s2_R[i] ^ s2_triples[j];	//messages2 for second OT
	}
	
	arg1[1] = messages1;
	arg2[1] = messages2;
	arg1[2] = &batch_size;
	arg2[2] = &batch_size;
    uint8_t* output1 = malloc(sizeof(uint8_t) * batch_size * 8), *output2 = malloc(sizeof(uint8_t) * batch_size * 8);
	uint16_t* choices1 = malloc(sizeof(uint16_t) * batch_size), *choices2 = malloc(sizeof(uint16_t) * batch_size);
    if(!output1 || !output2 || !choices1 || !choices2){
        printf("could not allocate space\n");
        return -1;
    }
	
	for(int i = 0; i < batch_size; i++){
        j = i * 3;
		choices1[i] = s2_triples[j + 1];
		choices2[i] = s1_triples[j + 1];
	}

	pthread_create(&send_thread1, NULL, OTeSendThread, arg1);
	OTeRecv(output1, choices1, batch_size);
	pthread_join(send_thread1, NULL);
	
	pthread_create(&send_thread2, NULL, OTeSendThread, arg2);
	OTeRecv(output2, choices2, batch_size);
	pthread_join(send_thread2, NULL);
    servers_communicate();
	
    free(messages1);
    free(messages2);
    free(choices1);
    free(choices2);
	//bool X1[batch_size], X2[batch_size];
    bool* X1 = malloc(sizeof(uint16_t) * batch_size), *X2 = malloc(sizeof(uint16_t) * batch_size);
    if(!X1 || !X2){
        printf("could not allocate space\n");
        return -1;
    }
    
	for(int i = 0; i < batch_size; i++){
		j = i * 8;
		X1[i] = output1[j];
		X2[i] = output2[j];
	}
    free(output1);
    free(output2);
    
    
	for(int i = 0; i < batch_size; i++){
		j = 3 * i;
		//server 1 acts as the sender, sending (r1, r1 ^ a1)
		//server 2 selects with b2 to learn x2 = a1b2 ^ r1
		//x2 = oblivious_transfer(s1_R[i], s1_R[i] ^ s1_triples[j], s2_triples[j + 1]);
		//server 2 calculates c2 as follows, according to the standard protocol [2]
		s2_triples[j + 2] =  X2[i] ^ s2_R[i] ^ (s2_triples[j] * s2_triples[j + 1]);
		//now reverse roles
		//x1 = oblivious_transfer(s2_R[i], s2_R[i] ^ s2_triples[j], s1_triples[j + 1]);	
		s1_triples[j + 2] = X1[i] ^ s1_R[i] ^ (s1_triples[j] * s1_triples[j + 1]);
	}
    free(s1_R);
    free(s2_R);
    free(X1);
    free(X2);
    return 1;
}

//boolean-to-arithmetic conversion for an array of bits seen in [2], but parallelised
void b2a_convert(int* output1, int* output2,  bool* input1, bool* input2, struct dabit* s1_dabits, struct dabit* s2_dabits){
	//server 1 calculates intermediate values V1
	bool V1[n];
	for(int i = 0; i < n; i++)
		V1[i] = input1[i] ^ s1_dabits[i].b;
	
	//server 2 does likewise
	bool V2[n];
	for(int i = 0; i < n; i++)
		V2[i] = input2[i] ^ s2_dabits[i].b;
	
	//servers share V in the clear
    servers_communicate();
	bool V[n];
	for(int i = 0; i < n; i++)
		V[i] = V1[i] ^ V2[i];
	
	//server 1 calculates output x as x = v + [b]^A_1 - 2v[b]^A_1 ([b]^A is the arithmetic share of the dabit)
	for(int i = 0; i < n; i++)
		output1[i] = FF_convert(V[i] + s1_dabits[i].a - (2 * V[i] * s1_dabits[i].a), FF_size);
	//server 2 calculates x as x = [b]^A_2 - 2v[b]^A_2
	for(int i = 0; i < n; i++)
		output2[i] = FF_convert(s2_dabits[i].a - (2 * V[i] * s2_dabits[i].a), FF_size);
}

int aggregate_2D(int* array, int bit_to_aggregate){ //aggregate a '2D' array of only the respective bit, per record
	int acc = 0;
	for(int i = 0; i < n; i++)
		acc += array[(i * L) + bit_to_aggregate];	
	return acc;
}

int aggregate_1D(int* array, int len){ //aggregate a 1D array where every value is to be aggregated
	int acc = 0;
	for(int i = 0; i < len; i++)
		acc += array[i];
	return acc;
}

int main(int argc, char* argv[]){
	int total_bits;
    clock_t start_time = 0, end_time = 0;
    double exec_time;
    int rsize = 3;
    bool cout = true;
    bool light = true & cout;
    
	//parse system arguments with modest error checking
	if(argc == 4 || argc == 5){
		bool failure = false;
		// atoi function only suitable in trusted environment
		int n_test = atoi(argv[1]);
		int m_test = atoi(argv[2]);
		int L_test = atoi(argv[3]);

		if(n_test < 1 || n_test > 1000000){
			printf("n (first argument) should be between 1 and 1000\n");
			failure = true;
		}
		if(m_test < 1 || m_test > 100){
			printf("m (second argument) should be between 1 and 100\n");
			failure = true;
		}
        if(L_test < 1 || L_test > 32){
			printf("L (third argument) should be between 1 and 32\n");
			failure = true;
		}
		if(argc == 5){
			if(strcmp("v", argv[4]) == 0)
				verbose = true;
			else{
				printf("Third argument should be \"v\" for verbose or nothing\n");
				failure = true;
			}
		}

		if(failure){
			printf("failure\n");
			return 1;
		}
		n = n_test;
		m = m_test;
		L = L_test;
        line = m * L;
		total_bits = n * line;

		FF_size = n + 1;
		printf("FF_size = %d\n", FF_size);
			
	}	
	else{
		printf("Use 3 args for n, m and L, and optionally \"v\" for verbose\n");
		return 1;
	}
	if(sodium_init() < 0){
		printf("Error initialising sodium library\n");
                return 1;
	}
    
	bool D[n][line], D1[n][line], D2[n][line];
	//generate n records with line bits of information each
	generate_records(D, D1, D2);
		
	if(verbose)
		print_records(D, total_bits);
	//int ret = intersect(server1_SS, server2_SS);
	//printf("Intersection count is: %d\n", ret);	
	
	char readBuf[32];
	printf("Which attributes do you wish to include? Please enter comma-seperated integers or type 'all'\n");
	fgets(readBuf, sizeof(readBuf), stdin);

	int intersection_indices[m];
	int index_len = 0;
    int query_len = 0;

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
		for(int i = 0; i < L; i++){
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
				if(num < 0){
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
				break;
			} else{
				printf("bad character %c\n", *endptr);
				return 1;
			}
		}
	}

	if(index_len == 0){
		printf("please provide an attribute\n");
		return 1;
	}

    char readBuf2[256];
	printf("Please enter your data under the specified attributes you just gave, as a bitstring\n");
	fgets(readBuf2, sizeof(readBuf2), stdin);
    
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
    bool query[query_len], q1[query_len], q2[query_len];
    for(int i = 0; i < query_len; i++){
        temp = readBuf2[i];
        query[i] = atoi(&temp);
    }

    secret_share(query, q1, q2, query_len);
    
	int no_of_multis = n * (query_len - 1); //number of multiplications
    bool Z1[n], Z2[n]; //output arrays
    struct dabit s1_dabits[n]; //server 1 share of dabits
    struct dabit s2_dabits[n]; //likewise
    generate_dabits(s1_dabits, s2_dabits, n);
    
    //consider only the relevant data specified by the query
    bool V1[n][query_len], V2[n][query_len];
    for(int record = 0; record < n; record++){
        for(int i = 0; i < index_len; i++)
            for(int l = 0; l < L; l++){
                V1[record][i * L + l] = D1[record][intersection_indices[i] * L + l];
                V1[record][i * L + l] ^= q1[i * L + l];
                V2[record][i * L + l] = D2[record][intersection_indices[i] * L + l];
                V2[record][i * L + l] ^= q2[i * L + l] ^ !cout; //negate only if using standard EQ
            }
    }
    
    if(cout){
        int j = query_len, depth = 0, noOTs = 0;
        int js[32];
        js[0] = j;
        while(j > rsize){
            if(depth > 32){
                printf("need bigger js array\n");
                return -1;
            }
            noOTs += j;
            j = (int)ceil(log2(j)) + 1;
            depth++;
            js[depth] = j;
        }
        noOTs *= n;
        int exp = (int)pow(2, rsize) - 2;
        //int R[n][depth][query_len], S[n][depth][query_len], A[n][depth][query_len], B[n][depth][query_len];
        //int r[n][exp], s[n][exp], a[n][exp], b[n][exp];
        int (*R)[depth][query_len] = malloc(sizeof(int) * n * depth * query_len), (*S)[depth][query_len] = malloc(sizeof(int) * n * depth * query_len), (*A)[depth][query_len] = malloc(sizeof(int) * n * depth * query_len), (*B)[depth][query_len] = malloc(sizeof(int) * n * depth * query_len);
        if(!R || !S || !A || !B){
            printf("could not allocate\n");
            return -1;
        }
        if(light){
            no_of_multis = n * (rsize - 1);
            printf("number of multiplications = %d\n", no_of_multis);
            printf("number of OTs = %d\n", noOTs);
            bool T1[3 * no_of_multis], T2[3 * no_of_multis]; //T is the set of beaver triples
            if(generate_beaver_triples(T1, T2, no_of_multis) == -1){
                printf("bad\n");
                return -1;
            }
            couteauPrepLight(n, depth, query_len, exp, R, S, A, B, rsize, noOTs, js);
            double acc = 0.;
            int repetitions = 10;
            artificial_delay = 0.;
            for(int i = 0; i < repetitions; i++){
                start_time = clock();
                couteauETLight(depth, query_len, exp, V1, V2, T1, T2, Z1, Z2, R, S, A, B, rsize, js);
                end_time = clock();
                acc += (double)(end_time - start_time) / CLOCKS_PER_SEC;
            }
            exec_time = (acc + artificial_delay) / repetitions;
            printf("execution time = %f\n", exec_time);
        }
        else{
            int (*r)[exp] = malloc(sizeof(int) * n * exp), (*s)[exp] = malloc(sizeof(int) * n * exp), (*a)[exp] = malloc(sizeof(int) * n * exp), (*b)[exp] = malloc(sizeof(int) * n * exp);
            if(!r || !s || !a || !b){
                printf("could not allocate\n");
                return -1;
            }
            couteauPrep(n, depth, query_len, exp, R, S, A, B, r, s, a, b, rsize, noOTs, js);
            artificial_delay = 0.;
            double acc = 0.;
            int repetitions = 10;
            for(int i = 0; i < repetitions; i++){
                start_time = clock();
                couteauET(depth, query_len, exp, V1, V2, Z1, Z2, R, S, A, B, r, s, a, b, rsize, js);
                end_time = clock();
                acc += (double)(end_time - start_time) / CLOCKS_PER_SEC;
            }
            exec_time = (acc + artificial_delay) / repetitions;
            printf("execution time = %f\n", exec_time);
            free(r);
            free(s);
            free(a);
            free(b);
        }
        free(R);
        free(S);
        free(A);
        free(B);
        return 0;
    }
    else{
        bool T1[3 * no_of_multis], T2[3 * no_of_multis]; //T is the set of beaver triples
        printf("number of multiplications = %d\n", no_of_multis);
        generate_beaver_triples(T1, T2, no_of_multis);
        artificial_delay = 0.;
        double acc = 0.;
        int repetitions = 10;
        for(int i = 0; i < repetitions; i++){
            start_time = clock();
            intersect(query_len, V1, V2, T1, T2, Z1, Z2);
            end_time = clock();
            acc += (double)(end_time - start_time) / CLOCKS_PER_SEC;
        }
        exec_time = (acc + artificial_delay) / repetitions;
        printf("execution time = %f\n", exec_time);
    }
    
	int Z1_arith[n], Z2_arith[n]; //arithmetic shares of the intersection values, Z1 and Z2

	b2a_convert(Z1_arith, Z2_arith, Z1, Z2, s1_dabits, s2_dabits);

	int s1_total = aggregate_1D(Z1_arith, n);
	int s2_total = aggregate_1D(Z2_arith, n);
    
    
	printf("the grand total is %d\n", FF_convert(s1_total + s2_total, FF_size));
	return 0;
}
