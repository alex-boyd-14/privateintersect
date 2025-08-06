// libote_wrapper.h
#ifndef LIBOTE_WRAP_H
#define LIBOTE_WRAP_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void OTeSend(const uint16_t* messages1, const uint16_t* messages2, const int noOTs);
void OTeRecv(uint8_t* retMsgs, const uint16_t* choices, const int noOTs);

#ifdef __cplusplus
}
#endif
#endif // LIBOTE_WRAP_H

