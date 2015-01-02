/* rndphrase.c
 *
 * Author: Philip Munksgaard <pmunksgaard@gmail.com>
 * Date: 2014-12-29
 *
 * This whole thing is pretty much a direct port of the implementation from
 * brinchj's original rndphrase.js:
 * https://github.com/brinchj/rndphrase
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define RotL(a,b) (((a) << (b)) | ((a) >>(32-b)))

// For info on CubeHash see: http://cubehash.cr.yp.to/
// Init vector was computed by 10r rounds as described in the specification

// From original javascript rndphrase implementation
static u_int32_t INIT[32] = {0x830b2bd5, 0x273d616f, 0xd785876a, 0x4a500218,
                             0xa5388963, 0xeeb702fb, 0x47547842, 0x459f8d89,
                             0x8727a1c8, 0xba40bd48, 0xcef47fe8, 0x2543c273,
                             0x5c033052, 0xae9fcd63, 0x2d4541bd, 0xe6b6cb0d,
                             0xcb8a9cdf, 0x579f5b67, 0xb2ae0096, 0x8180af6e,
                             0x51ebdf0c, 0xa597cd2b, 0xf91f981f, 0x7ab29a62,
                             0x01ad72d9, 0x46e6c075, 0xc6d1337e, 0x0a293d6f,
                             0x90c438ac, 0x38be153f, 0x32aa288f, 0xfc5eca8a};

static char HEX_TABLE[] = "0123456789abcdef";

static char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz0123456789";

void int_to_hex(char* buf, u_int32_t v){
  int i;
  for (i = 0; v != 0; i++, v = v >> 8) {
    buf[i*2] = HEX_TABLE[(v >> 4) & 0xF];
    buf[i*2+1] = HEX_TABLE[v & 0xF];
  }

  return;
}

void swap(u_int32_t arr[], int i, int j) {
  u_int32_t tmp = arr[i];
  arr[i] = arr[j];
  arr[j] = tmp;
}


void transform(u_int32_t state[32]) {
  int i, r;
  u_int32_t  y[16];

  for(i = 0; i < 16; ++i) {
    y[i] = 0;
  }

  for (r = 0;r < 8; ++r) {
    for (i = 0;i < 16; ++i) state[i+16] += y[i^8] = state[i];
    for (i = 0;i < 16; ++i) state[i]     = RotL(y[i],7)^state[i+16];
    for (i = 0;i < 16; ++i) y[i^2]       = state[i + 16];
    for (i = 0;i < 16; ++i) state[i+16]  = y[i] + state[i];
    for (i = 0;i < 16; ++i) y[i^4]       = state[i];
    for (i = 0;i < 16; ++i) state[i]     = RotL(y[i],11) ^ state[i+16];
    for (i = 0; i < 16; i+=2) {
      swap(state, i+16, i+17);
    }
  }
}

void hash(size_t size, char data[size], char s[64]) {
  // init state
  int i;

  u_int32_t state[32];
  for (i = 0; i < 32; i++) state[i] = INIT[i];

  // This needs to be an unsigned char for us to be able
  // to add a 128 byte.
  unsigned char * tmp = malloc(sizeof(unsigned char) * size + 1);
  for (i=0; i<size; i++) tmp[i] = data[i];

  // update with data
  tmp[size] = 128;
  for (i = 0; i <= size; i++) {
    state[0] ^= tmp[i];
    transform(state);
  }

  free(tmp);

  // finalize
  state[31] ^= 1;
  for (i = 0; i < 10; i++) transform(state);

  // convert to hex
  for (i = 0; i < 8; i++) int_to_hex(&s[i*8], state[i]);
}

void pack(char msg[64], char s[16]) {
  // Note: modulus introduces a bias
  // use 2 bytes to pick the letter to relax this
  char buf[4];
  for(int i = 0; i < 64; i += 4) {

    memcpy(buf, msg+i, 4);
    long int number = (long int)strtol((const char*)buf, NULL, 16);
    s[i / 4] = ALPHABET[number % 36];
  }
}

void rndphrase(int slen, char seed[slen],
              int hlen, char host[hlen],
              int plen, char passwd[plen],
              char result[16]) {

  int tmp, i;

  // seed + passwd + host + '$' + 2 * hash_len + NULL
  int maxlen = slen + hlen + plen + 128 + 2;
  char* buf1 = malloc(sizeof(char) * maxlen);
  char* buf2 = malloc(sizeof(char) * maxlen);
  for (i=0; i<maxlen; i++) { buf1[i] = 0; buf2[i] = 0; }

  // Hash the seed
  hash(strlen(seed), seed, buf1);

  // Prepare passwd + '$' + host
  tmp = strlen(passwd);
  strncpy(buf2, passwd, tmp);
  buf2[tmp] = '$';
  strncpy(buf2 + tmp + 1, host, strlen(host));

  // Hash it in place
  hash(tmp + 1 + strlen(host), buf2, buf2);

  // Append the hashed seed (len 64) and hash in place
  strncpy(buf2+64, buf1, 64);
  buf2[128] = 0;
  hash(128, buf2, buf2);
  buf2[64] = 0;

  // Append the password and hash in place
  strncpy(buf2+64, passwd, strlen(passwd));
  hash(64 + strlen(passwd), buf2, buf2);
  buf2[64] = 0;

  // Pack it
  pack(buf2, result);
  free(buf1);
  free(buf2);

}
