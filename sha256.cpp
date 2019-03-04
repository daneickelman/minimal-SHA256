/**
SHA256 hashing function
	msgRaw - pointer to original byte stream
	msgRawLen - length of the message in bytes
	hash - pointer to write resulting hash to
*/

#include "sha256.h"

int hashSHA256(BYTE* msgRaw, uint64_t msgRawLen, BYTE* hash) {

	//Preprocessing - padding message and appending length in bigendian format
	uint64_t msgLen = msgRawLen + (64 - msgRawLen % 64);
	BYTE *msg = new BYTE[msgLen];
	memset(msg, 0, msgLen);
	memcpy(msg, msgRaw, msgRawLen);
	msg[msgRawLen] = 1 << 7;

	uint64_t nBits = msgRawLen*8;
	nBits = (nBits & 0x00000000FFFFFFFF) << 32 | (nBits & 0xFFFFFFFF00000000) >> 32;
	nBits = (nBits & 0x0000FFFF0000FFFF) << 16 | (nBits & 0xFFFF0000FFFF0000) >> 16;
	nBits = (nBits & 0x00FF00FF00FF00FF) << 8  | (nBits & 0xFF00FF00FF00FF00) >> 8;
	memcpy(&msg[msgLen - 8], &nBits, 8);

	//Initialization
	WORD *M = new WORD[msgLen];
	WORD H[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	//Hash computation
	for (int i = 0; i < msgLen / 64; i++) {
		for (int j = 0; j < 64; j++) {
			if (j < 16) {
				M[i*64 + j] = (msg[4 * j] << 24) | (msg[4 * j + 1] << 16) | (msg[4 * j + 2] << 8) | (msg[4 * j + 3]);
			}
			else {
				M[i*64 + j] = LSIG1(M[i*64 + j - 2]) + M[i*64 + j - 7] + LSIG0(M[i*64 + j - 15]) + M[i*64 + j - 16];
			}
		}

		WORD a = H[0];
		WORD b = H[1];
		WORD c = H[2];
		WORD d = H[3];
		WORD e = H[4];
		WORD f = H[5];
		WORD g = H[6];
		WORD h = H[7];
		WORD t1, t2;

		for (int j = 0; j < 64; ++j) {
			t1 = h + USIG1(e) + CH(e, f, g) + k[j] + M[i*64 + j];
			t2 = USIG0(a) + MAJ(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}

	//Byte reverse to return hash in big endian format
	for (int i = 0; i < 8; i++) {
		H[i] = (H[i] & 0x0000FFFF) << 16 | (H[i] & 0xFFFF0000) >> 16;
		H[i] = (H[i] & 0x00FF00FF) << 8  | (H[i] & 0xFF00FF00) >> 8;
	}
	
	memcpy(hash, H, 8 * sizeof(WORD));

	delete[] msg;
	delete[] M;

	return 0;
}