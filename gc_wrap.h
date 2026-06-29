#ifndef GC_WRAP_H
#define GC_WRAP_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
// party: 1 = server1/garbler, 2 = server2/evaluator
// peer_ip: server2's IP from server1's perspective, NULL from server2's
// Returns this server's XOR share of (sum > threshold)
uint8_t gc_threshold_check(int party, uint32_t share, uint32_t p, uint32_t threshold, const char *peer_ip, int port);
#ifdef __cplusplus
}
#endif
#endif
