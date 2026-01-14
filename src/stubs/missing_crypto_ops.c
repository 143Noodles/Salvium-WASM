#include "crypto/crypto-ops.h"
#include <string.h>

/* Constants */
static const unsigned char c_A[32] = {
    0x06, 0x6D, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; /* 486662 */
static const unsigned char c_sqrt_m486664[32] = {
    0x06, 0x7e, 0x45, 0xff, 0xaa, 0x04, 0x6e, 0xcc, 0x82, 0x1a, 0x7d,
    0x4b, 0xd1, 0xd3, 0xa1, 0xc5, 0x7e, 0x4f, 0xfc, 0x03, 0xdc, 0x08,
    0x7b, 0xd2, 0xbb, 0x06, 0xa0, 0x60, 0xf4, 0xed, 0x26, 0x0f};

int fe_equal(const fe a, const fe b) {
  unsigned char ab[32], bb[32];
  fe_tobytes(ab, a);
  fe_tobytes(bb, b);
  return memcmp(ab, bb, 32) == 0;
}

int fe_sqrt_mont(fe v, const fe u) {
  fe u2, u3, rhs, A, tmp, check, neg_check;
  fe_sq(u2, u);
  fe_mul(u3, u2, u);
  fe_frombytes_vartime(A, c_A);
  fe_mul(tmp, A, u2);
  fe_add(rhs, u3, tmp);
  fe_add(rhs, rhs, u);

  fe_pow22523(v, rhs);
  fe_sq(check, v);

  /* Check v^2 == rhs */
  if (fe_equal(check, rhs))
    return 0;

  /* Check -v^2 == rhs */
  fe_neg(neg_check, check);
  if (fe_equal(neg_check, rhs)) {
    fe_mul(v, v, fe_sqrtm1);
    return 0;
  }
  return -1;
}

void mont_to_ed(fe x, fe y, const fe u, const fe v) {
  fe one, num, den, inv, s;
  fe_1(one);
  fe_sub(num, u, one);
  fe_add(den, u, one);
  fe_invert(inv, den);
  fe_mul(y, num, inv);

  fe_frombytes_vartime(s, c_sqrt_m486664);

  /* x = s * u * (1/v) */
  fe_mul(x, s, u);
  fe_invert(inv, v);
  fe_mul(x, x, inv);
}

void ge_from_xy(ge_p3 *p, const fe x, const fe y) {
  fe_copy(p->X, x);
  fe_copy(p->Y, y);
  fe_1(p->Z);
  fe_mul(p->T, x, y);
}

/* Stubs for undefined symbols (v1.0.7 legacy/unused) */

/* tools::Notify::notify(char const*, char const*, ...) */
void _ZNK5tools6Notify6notifyEPKcS2_z(void *this_ptr, const char *a,
                                      const char *b, ...) {
  /* No-op */
}

/* tools::wallet2::get_client_signature() */
void _ZNK5tools7wallet220get_client_signatureEv(void *this_ptr) {
  /* No-op: Returns garbage if return value expected, but likely unused in WASM
   */
}
