#include <emp-sh2pc/emp-sh2pc.h>
//#include <emp-tool/emp-tool.h>
//#include <emp-ot/emp-ot.h>
#include "gc_wrap.h"
using namespace emp;

extern "C" uint8_t gc_threshold_check(int party, uint32_t share, uint32_t p,
                                       uint32_t threshold, const char *peer_ip,
                                       int port)
{
    NetIO io(party == ALICE ? nullptr : peer_ip, port);
    SH2PCSession sess(&io, party);

    using Ctx    = SH2PCSession::ctx_t;
    using UInt25 = UInt_T<Ctx, 25>;  // 25 bits covers 2p up to ~33M

    auto s1      = sess.input<UInt25>(ALICE, party == ALICE ? share : 0);
    auto s2      = sess.input<UInt25>(BOB,   party == BOB   ? share : 0);
    auto p_const = sess.input<UInt25>(PUBLIC, p);
    auto T_const = sess.input<UInt25>(PUBLIC, threshold);

    // Modular reduction
    auto raw_sum  = s1 + s2;
    auto reduced  = raw_sum - p_const;
    auto wrapped  = raw_sum >= p_const;
    auto sum      = raw_sum.select(wrapped, reduced);
    // Threshold comparison
    auto result   = sum > T_const;

    // ALICE picks her share
    uint8_t r = (party == ALICE) ? (rand() & 1) : 0;

    // Input r into the circuit as ALICE's private value
    using Bit = Bit_T<Ctx>;
    auto r_bit   = sess.input<Bit>(ALICE, r);

    // XOR the result with r inside the circuit
    auto masked  = result ^ r_bit;

    // Reveal only the masked result to BOB
    uint8_t result_share;
    if (party == ALICE) {
        sess.reveal(masked, BOB);  // BOB learns result XOR r
        result_share = r;          // ALICE keeps r
    } else {
        result_share = (uint8_t)sess.reveal(masked, BOB).value();
    }

    return result_share;
}
