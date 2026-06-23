#ifndef LIBOTE_WRAP_H
#define LIBOTE_WRAP_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int to_bytescpp(int no_bits);
void OTeSend1(const uint8_t* messages1, const uint8_t* messages2, const int noOTs);
void OTeSend32(const uint32_t* messages1, const uint32_t* messages2, const int noOTs);
void OTeRecv1(uint8_t* retMsgs, const uint8_t* choices, const int noOTs);
void OTeRecv32(uint32_t* retMsgs, const uint8_t* choices, const int noOTs);

#ifdef __cplusplus
}
#endif
#endif

