#include "libote_wrap.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <sodium.h>
#include <pthread.h>

bool verbose;
int n, L, FF_size; //n = number of clients, L = bitlength per client

struct dabit{
	int b;
	int a;
};

int oblivious_transfer(int x1, int x2, bool c){
	if(c) return x2; else return x1;}

//finite field conversion, (%) operator close but doesn't deal with negatives properly
int FF_convert(int x){
	if(x >= 0) return x % FF_size;
	else return (x % FF_size) + FF_size;
}

void* OTeSendThread(void* arg){
	void** unpack = (void**)arg;
	uint16_t* messages1 = (uint16_t*)unpack[0];
	uint16_t* messages2 = (uint16_t*)unpack[1];
	int size = *(int*)unpack[2];
	OTeSend(messages1, messages2, size);
	return NULL;
	//	Y2[i] = oblivious_transfer(X[i], FF_convert(X[i] + B1[i]), B2[i]);
}

//dabitgen algorithm according to [1] but parallelised
void generate_dabits(struct dabit* s1_dabits, struct dabit* s2_dabits){
	//s1 chooses n random bits B1
	int min_bytes = ceil(n/8.0);	//need to increase capacity for more clients!! 
	uint16_t B1[n];
	char r1_buf[min_bytes];
        randombytes_buf(r1_buf, min_bytes);
	uint32_t r1 = randombytes_uniform((int)pow(2, n));
	for(int i = 0; i < n; i++)
		B1[i] = (r1 >> i) & 1;

	//s1 chooses n random field elements X and sets y1 = -x mod p for each one 	
	uint16_t X[n];
	uint16_t Y1[n]; 
	char x_buf[32];	//32 byte max finite field size should be fine
	for(int i = 0; i < n; i++){
		randombytes_buf(x_buf, 32);
		X[i] = randombytes_uniform(FF_size);
		Y1[i] = FF_convert(-X[i]); 
	}

	//s2 chooses n random bits B2
	uint16_t B2[n]; //choices
	char r2_buf[min_bytes];
        randombytes_buf(r2_buf, min_bytes);
	uint32_t r2 = randombytes_uniform((int)pow(2, n));
	for(int i = 0; i < n; i++)
		B2[i] = (r2 >> i) & 1;
	
	//s1 acts as OT sender, sending (x, x + b1), s2 acts as receiver with choice bit b2
	uint16_t Y2[n]; 
	uint8_t output[n * 8];
	//for(int i = 0; i < n; i++)
	//	Y2[i] = oblivious_transfer(X[i], FF_convert(X[i] + B1[i]), B2[i]);
	pthread_t thread2;
	uint16_t messages2 [n];
	for(int i = 0; i < n; i++)
		messages2[i] = FF_convert(X[i] + B1[i]);
	void* arg[3];
	arg[0] = X; //messages1
	arg[1] = messages2;
	arg[2] = &n;
	
	pthread_create(&thread2, NULL, OTeSendThread, arg);
	OTeRecv(output, B2, n);
	pthread_join(thread2, NULL);
	
	for(int i = 0; i < n; i++)
		Y2[i] = output[i * 8];

	//both servers compute a_i = b_i - 2*y_i and output values
	uint16_t A1[n];
	for(int i = 0; i < n; i++){
		A1[i] = FF_convert(B1[i] - (2 * Y1[i]));
		s1_dabits[i].b = B1[i];
		s1_dabits[i].a = A1[i];
	}

	uint16_t A2[n];
	for(int i = 0; i < n; i++){
		A2[i] = FF_convert(B2[i] - (2 * Y2[i]));
		s2_dabits[i].b = B2[i];
		s2_dabits[i].a = A2[i];
	}
}

// pre-compute a batch of beaver triples in parallel
void generate_beaver_triples(bool* s1_triples, bool* s2_triples, int batch_size){

	int total_bits = 3 * batch_size;
	int total_bytes = ceil((double)total_bits / 8);
	
	//server 1 samples 'batch_size' bit doubles (a1, b2) plus 'batch_size' random bits R1 for the OTs
	char s1_buffer[total_bytes];
	uint16_t s1_R[batch_size];
	randombytes_buf(s1_buffer, total_bytes);

	//random number of suitable length using intermediate variable r_i, not to be confused with R
	uint32_t r1 = randombytes_uniform(2 * (int)pow(2, total_bits));

	//extract random data similar to generate_clients()
	int j;	
	for(int i = 0; i < batch_size; i++){
		j = 3 * i;	
		s1_triples[j] = (r1 >> j) & 1;
		s1_triples[j + 1] = (r1 >> (j + 1)) & 1;
		s1_R[i] = (r1 >> (j + 2)) & 1;
	}

	//server 2 samples n bit doubles in exactly the same way
	char s2_buffer[total_bytes];
	uint16_t s2_R[batch_size];
	randombytes_buf(s2_buffer, total_bytes);
	uint32_t r2 = randombytes_uniform(2 * (int)pow(2, total_bits));
	
	for(int i = 0; i < batch_size; i++){
		j = 3 * i;
		s2_triples[j] = (r2 >> j) & 1;
		s2_triples[j + 1] = (r2 >> (j + 1)) & 1;
		s2_R[i] = (r2 >> (j + 2)) & 1;
	}

	//perform 2 OTs
	pthread_t send_thread1, send_thread2;
	void* arg1[3], * arg2[3];
	arg1[0] = s1_R; //messages1 for first OT
	arg2[0] = s2_R;	//messages1 for second OT
	uint16_t messages2_1[batch_size], messages2_2[batch_size];
	for(int i = 0; i < batch_size; i++){
		messages2_1[i] = s1_R[i] ^ s1_triples[3 * i];	//messages2 for first OT
		messages2_2[i] = s2_R[i] ^ s2_triples[3 * i];	//messages2 for second OT
	}
	
	arg1[1] = messages2_1;
	arg2[1] = messages2_2;
	arg1[2] = &batch_size;
	arg2[2] = &batch_size;	
	
	uint8_t output1[batch_size * 8], output2[batch_size * 8];
	uint16_t choices1[batch_size], choices2[batch_size];
	
	for(int i = 0; i < batch_size; i++){
		choices1[i] = s2_triples[(i * 3) + 1];
		choices2[i] = s1_triples[(i * 3) + 1];
	}

	pthread_create(&send_thread1, NULL, OTeSendThread, arg1);
	OTeRecv(output1, choices1, batch_size);
	pthread_join(send_thread1, NULL);
	
	pthread_create(&send_thread2, NULL, OTeSendThread, arg2);
	OTeRecv(output2, choices2, batch_size);
	pthread_join(send_thread2, NULL);
	
	bool X1[batch_size], X2[batch_size];
	for(int i = 0; i < batch_size; i++){
		j = i * 8;
		X1[i] = output1[j];
		X2[i] = output2[j];
	}

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

}

//generate n clients with L bits of information each
//s1_clients is server 1's share of the client data, s2 likewise
/* the sodium library works by generating one
number from a given number of random bytes rather than
a random bitstring of given length. Therefore, in the
code below, an integer of suitable length is generated,
before being converted to binary. Each bit in the binary
representation becomes the client data.
*/

int generate_clients(bool* clients, bool* s1_clients, bool* s2_clients, int total_bits){

	int total_bytes = ceil((double)total_bits / 8);
	//2* because need random bits for secret share too
	char buffer[2 * total_bytes];
	randombytes_buf(buffer, 2 * total_bytes);

	//random number of suitable length
	uint32_t r = randombytes_uniform(2 * (int)pow(2, total_bits));
	
	int j1, j2;
	for(int i = 0; i < total_bits; i++){
		//jx is the bit to extract
		j1 = total_bits - 1 - i;
		j2 = (total_bits * 2) - 1 - i; 
		//extract the jth bit of binary rep. of r and set it to client data
		clients[i] = (r >> j1) & 1;
		//choose another random bit for first secret share
		s1_clients[i] = (r >> j2) & 1;
		//set second share such that s2 = s1 XOR S
		s2_clients[i] = s1_clients[i] ^ clients[i];
	}
	return 0;
}

void print_clients(bool* clients, int total_bits){
	for(int i = 0; i < total_bits; i++){
		if(i % L == 0)
			printf("(%d, ", clients[i]);
		else if(i % L == L - 1)
			printf("%d)\n", clients[i]);
		else printf("%d, ", clients[i]);
	}
	printf("\n");
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
	bool V[n];
	for(int i = 0; i < n; i++)
		V[i] = V1[i] ^ V2[i];
	
	//server 1 calculates output x as x = v + [b]^A_1 - 2v[b]^A_1 ([b]^A is the arithmetic share of the dabit)
	for(int i = 0; i < n; i++)
		output1[i] = FF_convert(V[i] + s1_dabits[i].a - (2 * V[i] * s1_dabits[i].a));
	//server 2 calculates x as x = [b]^A_2 - 2v[b]^A_2
	for(int i = 0; i < n; i++)
		output2[i] = FF_convert(s2_dabits[i].a - (2 * V[i] * s2_dabits[i].a));
}

int aggregate_2D(int* array, int bit_to_aggregate){ //aggregate a '2D' array of only the respective bit, per client
	int acc = 0;
	for(int i = 0; i < n; i++)
		acc += array[(i * L) + bit_to_aggregate];	
	return acc;
}

int aggregate_1D(int* array){ //aggregate a 1D array where every value is to be aggregated
	int acc = 0;
	for(int i = 0; i < n; i++)
		acc += array[i];
	return acc;
}

//D_i is each server's boolean share of the client data, I_i is the computed intersection shares
void intersect(bool* D1, bool* D2, bool * T1, bool* T2, bool* Z1, bool* Z2, int* intersect_indices, int index_len, int total_bits){
	int j = 0;
	int no_rounds = (int)ceil(log2(index_len));

	//intermediate array so we don't destroy client data
	//may as well use 2D array instead of flattened 1D since only used locally anyway
	bool I1[n][L], I2[n][L];
	for(int i = 0; i < n; i++)
		for(int ii = 0; ii < L; ii++){
			I1[i][ii] = D1[j];
			I2[i][ii] = D2[j++];
		}

	j = 0;
	int jcheckpoint;
	int index1, index2, spacing;
	int no_pairs = index_len;
	bool D1_buf[n], D2_buf[n], E1_buf[n], E2_buf[n], D[n], E[n]; //buffers for d1, d2,... values
	
	for(int round = 0; round < no_rounds; round++){
		no_pairs = index_len / 2; //e.g. if we have 7 indices, we have 3 pairs and 1 leftover
		index_len -= no_pairs;
		spacing = (int)pow(2, round);
		//printf("%d\n", no_pairs);
		for(int pair = 0; pair < no_pairs; pair++){
			index1 = intersect_indices[2*pair*spacing]; //first index of the pair 
			index2 = intersect_indices[spacing*(2*pair + 1)]; //second index of the pair 
			jcheckpoint = j;
			for(int i = 0; i < n; i++){
				//server 1 computes intermediate values d1 = x1 - a1
				D1_buf[i] = I1[i][index1] ^ T1[j];
				//e1 = y1 - b1
				E1_buf[i] = I1[i][index2] ^ T1[j + 1];

				//server 2 does similarly
				D2_buf[i] = I2[i][index1] ^ T2[j];
				E2_buf[i] = I2[i][index2] ^ T2[j + 1];
				j += 3;
			}
			j = jcheckpoint;
			//servers publish shares, i.e. server 1 sends D1_buf and E1_buf, server 2 similarly
			for(int i = 0; i < n; i++){
				//now we assume both servers have all parts to reconstruct D and E, and thus both calculate:
				D[i] = D1_buf[i] ^ D2_buf[i];
				E[i] = E1_buf[i] ^ E2_buf[i];
				//server 1 computes z1 as d*b1 + e*a1 + c1 and stores it in intermediate array I
				I1[i][index1] = D[i]*T1[j + 1] ^ E[i]*T1[j] ^ T1[j + 2];
				//server 2 computes z2 as d*e + d*b2 + e*a2 + c2
				I2[i][index1] = D[i]*E[i] ^ D[i]*T2[j + 1] ^ E[i]*T2[j] ^ T2[j + 2];
				j += 3;
			}
		}
	}
	
	//finish by setting the return arrays Z to the first index of the intermediate array
	for(int i = 0; i < n; i++){
		Z1[i] = I1[i][intersect_indices[0]];
		Z2[i] = I2[i][intersect_indices[0]];
	}
} 

int main(int argc, char* argv[]){
	int total_bits;	
	//parse system arguments with modest error checking
	if(argc == 3 || argc == 4){
		bool failure = false;
		// atoi function only suitable in trusted environment
		int n_test = atoi(argv[1]);
		int L_test = atoi(argv[2]);

		if(n_test < 1 || n_test > 1000){
			printf("n (first argument) should be between 1 and 1000\n");
			failure = true;
		}
		if(L_test < 2 || L_test > 1000){
			printf("L (second argument) should be between 2 and 1000\n");
			failure = true;
		}
		if(argc == 4){
			if(strcmp("v", argv[3]) == 0)
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
		L = L_test;
		total_bits = n * L;

		FF_size = n + 1;
		printf("FF_size = %d\n", FF_size);
			
	}	
	else{
		printf("Use 2 args for n and L, and optionally \"v\" for verbose\n");
		return 1;
	}
	if(sodium_init() < 0){
		printf("Error initialising sodium library\n");
                return 1;
	}
	//using flat 1D array to simulate 2D array, D is the client data
	bool D [total_bits], D1 [total_bits], D2 [total_bits];
	//generate n clients with L bits of information each   	
	generate_clients(D, D1, D2, total_bits);
		
	if(verbose)
		print_clients(D, total_bits);
	//int ret = intersect(server1_SS, server2_SS);
	//printf("Intersection count is: %d\n", ret);	
	
	char readBuf [32];
	printf("What intersections do you want? Please enter comma-seperated integers or type 'all'\n");
	fgets(readBuf, sizeof(readBuf), stdin);

	int intersection_indices [L];
	int index_len = 0;

	char * endptr;
   	long int num;

	if(!strncmp(readBuf, "all", 3)){
		index_len = L;
		for(int i = 0; i < L; i++)
			intersection_indices[i] = i;
	}

   	else{
		char * startptr = readBuf;
		for(int i = 0; i < L; i++){
   			num = strtol(startptr, &endptr, 10);
   			if(*endptr == ','){
				if(num < 0){
					printf("please enter a positive integer\n");
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
				if(num >= 1000){
					printf("please enter a number below 1000\n");
					return 1;
				}
				intersection_indices[i] = num - 1;
   				index_len = i + 1;
				break;
			} else{
				printf("bad character %c\n", *endptr);
				return 1;
			}
		}
	}

	if(index_len < 2){
		printf("please provide at least 2 intersections\n");
		return 1;
	}

	int no_of_multis = n * (index_len - 1); //number of multiplications
	bool T1[3 * no_of_multis], T2[3 * no_of_multis]; //T is the set of beaver triples
	bool Z1[n], Z2[n];
	generate_beaver_triples(T1, T2, no_of_multis);

	struct dabit s1_dabits[n]; //server 1 share of dabits
	struct dabit s2_dabits[n]; //likewise

	generate_dabits(s1_dabits, s2_dabits);
	
	intersect(D1, D2, T1, T2, Z1, Z2, intersection_indices, index_len, no_of_multis); 
	
	int Z1_arith[n], Z2_arith[n]; //arithmetic shares of the intersection values, Z1 and Z2

	b2a_convert(Z1_arith, Z2_arith, Z1, Z2, s1_dabits, s2_dabits);
	
	int s1_total = FF_convert(aggregate_1D(Z1_arith));
	int s2_total = FF_convert(aggregate_1D(Z2_arith));

	printf("the grand total is %d\n", FF_convert(s1_total + s2_total));	

	return 0;	
}

			//the following is the 'readable' version of the for loop
			/*

			//server 1 prepares variables
			x1 = D1[i*L + bits_to_intersect[0]];
			y1 = D1[i*L + bits_to_intersect[1]];
			a1 = T1[j];
			b1 = T1[j + 1];
			c1 = T1[j + 2];

			//server 1 computes intermediate values
			d1 = x1 ^ a1;
			e1 = y1 ^ b1;

			//server 2 prepares variables
			x2 = D2[i*L + bits_to_intersect[0]];
			y2 = D2[i*L + bits_to_intersect[1]];
			a2 = T2[j];
			b2 = T2[j + 1];
			c2 = T2[j + 2];

			//server 2 computes intermediate values
			d2 = x2 ^ a2;
			e2 = y2 ^ b2;

			//servers publish e and d shares
			d = d1 ^ d2;
			e = e1 ^ e2;

			//server 1 computes z1 as d*b1 + e*a1 + c1
			z1 = d*b1 ^ e*a1 ^ c1;
			//server 2 computes z2 as d*e + d*b2 + e*a2 + c2
			z2 = d*e ^ d*b2 ^ e*a2 ^ c2;

			Z1[i] = z1;
			Z2[i] = z2;*/
			
	/*for(int i = 0; i < 0; i++){	
		j = 3*i;
		//server 1 computes intermediate values d1 = x1 - a1
		d1 = D1[i*L + intersect_indices[0]] ^ T1[j];
		//e1 = y1 - b1
		e1 = D1[i*L + intersect_indices[1]] ^ T1[j + 1];

		//server 2 does likewise
		d2 = D2[i*L + intersect_indices[0]] ^ T2[j];
		e2 = D2[i*L + intersect_indices[1]] ^ T2[j + 1];

		//servers publish shares
		d = d1 ^ d2;
		e = e1 ^ e2;

		//server 1 computes z1 as d*b1 + e*a1 + c1
		Z1[i] = d*T1[j + 1] ^ e*T1[j] ^ T1[j + 2];
		//server 2 computes z2 as d*e + d*b2 + e*a2 + c2
		Z2[i] = d*e ^ d*T2[j + 1] ^ e*T2[j] ^ T2[j + 2];
	}*/

