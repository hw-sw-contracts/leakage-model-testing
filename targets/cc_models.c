#include <inttypes.h>
#include <stdbool.h>

uint32_t fpclen(uint32_t* data, int numbytes) {
  uint32_t bcount = 0, count;
  bool zeroing = false;
  int zcount = 0;
  uint32_t* slice;
  uint32_t lastword = -1;
  int numwords = numbytes / 4;

  for (slice = data; slice < data + numwords; slice++) {
    uint32_t word = *slice;
    int32_t iword = *(int32_t*)slice;
    if (word == 0) {
      // zero run
      if (lastword != 0) {
        // start a new zero run
        zcount = 0;
        bcount += 6;
      }
      zcount++;
      if (zcount > 8) {
        // zero-runs go up to 8 zeros max
        // so start a new run
        zcount -= 8;
        bcount += 6;
      }
    } else if (iword << 28 >> 28 == iword) {
      // 4-bit sign-extended
      bcount += 7;
    } else if (iword << 24 >> 24 == iword) {
      // one byte sign-extended
      bcount += 11;
    } else if (iword << 16 >> 16 == iword) {
      // halfword sign-extended
      bcount += 19;
    } else if (iword << 16 == 0) {
      // halfword zero-padded
      bcount += 19;
    } else if ((iword << 8 >> 8 & 0xffff0000 | (iword << 24 >> 24 & 0xffff)) == iword) {
      // two sign-extended halfwords
      bcount += 19;
    } else if ((word >> 24) == (word & 0xff) &&
        (word >> 16 & 0xff) == (word & 0xff) &&
         (word >> 8 & 0xff) == (word & 0xff)) {
      // repeated byte
      bcount += 11;
    } else {
      bcount += 35;
    }
    lastword = word;
  }
  return (bcount + 7) / 8;
}

int bs(int64_t num) {
  if (!num) return 1;
  for (int i = 2; i <= 32; i <<= 1) {
    int64_t n = num >> (i - 1);
    if (n == 0 || n == -1) return i;
  }
  return 64;
}

#define _BDI(blen, dlen) { \
      int64_t base = 0; \
      uint8_t* slice; \
      bool broke = false; \
      for (slice = data; slice < data + numbytes; slice += blen) { \
        int64_t iword; \
 \
        if (blen == 1) \
          iword = *(int8_t*)slice; \
        else if (blen == 2) \
          iword = *(int16_t*)slice; \
        else if (blen == 4) \
          iword = *(int32_t*)slice; \
        else if (blen == 8) \
          iword = *(int64_t*)slice; \
 \
        if (bs(iword) > dlen*8) { \
          if (!base) { \
            base = iword; \
          } \
          int64_t delta = iword - base; \
          if (bs(delta) > dlen*8) { \
            broke = true; \
            break; \
          } \
        } \
      } \
      if (!broke) return blen + numbytes / blen * dlen; \
}

uint32_t bdilen(uint8_t* data, uint32_t numbytes) {
  bool broke = false;

  // check for all-zero
  for (uint8_t* slice = data; slice < data + numbytes; slice += 8) {
    if (*(uint64_t*)slice){
      broke = true;
      break;
    }
  }
  if (!broke) return 1;

  // check for repeated 8-byte words
  broke = false;
  uint64_t base = *(uint64_t*)data;
  for (uint8_t* slice = data; slice < data + numbytes; slice += 8) {
    uint64_t word = *(uint64_t*)slice;
    if (word != base){
      broke = true;
      break;
    }
  }
  if (!broke) return 8;

  // actually try BDI
  // ordered from increasing size for 32- and 64-byte cache lines
  _BDI(8, 1);
  _BDI(4, 1);
  _BDI(8, 2);
  _BDI(2, 1);
  _BDI(4, 2);
  _BDI(8, 4);
  return numbytes;
}
