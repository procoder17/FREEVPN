#ifndef CURVE25519_H
#define CURVE25519_H

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);

#endif