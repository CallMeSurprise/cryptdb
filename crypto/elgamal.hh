#pragma once

#include <list>
#include <vector>
#include <NTL/ZZ.h>

struct elGamalCipher{
	NTL::ZZ c1, c2;
};
typedef struct elGamalCipher ElGamalCipher;

class ElGamal {
	public:
		void KeyGen(long);
		ElGamalCipher Encrypt(NTL::ZZ m);
		NTL::ZZ Decrypt(ElGamalCipher c);
	// private:
		NTL::ZZ pKey;
		NTL::ZZ sKey;
		NTL::ZZ prime;
		NTL::ZZ g;
};
	

