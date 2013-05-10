#include <crypto/elgamal.hh>
#include <iostream>
#include <NTL/ZZ.h>
#include <crypto/prng.hh>

using namespace std;
using namespace NTL;

void ElGamal::KeyGen(long length) {
	prime = GenPrime_ZZ(length,80);	// Generate prime
	g = RandomBnd(prime);		// Generator in mod prime
	sKey = RandomBnd(prime);	// sKey random number in [0,prime-1]
	PowerMod(pKey, g, sKey, prime); // Calculates g^x (mod prime)
}

ElGamalCipher ElGamal::Encrypt(ZZ m){
	ElGamalCipher cipher;
	ZZ k = RandomBnd(prime);		// sKey random number in [0,prime-1]
	PowerMod(cipher.c1,g,k,prime);		// c1 = g^k mod prime
	PowerMod(cipher.c2,pKey,k,prime);	// c2 = pKey^k
	MulMod(cipher.c2,m,cipher.c2,prime);	// c2 = m*pKey^k
	return cipher;
}

ZZ ElGamal::Decrypt(ElGamalCipher cipher){
	ZZ a,ret;
	PowerMod(a,cipher.c1,sKey,prime);
	InvMod(a,a,prime);
	MulMod(ret,cipher.c2,a,prime);
	return ret;
}

int main(){
	ElGamal elgamal;
	ElGamalCipher cipher;
	ZZ message;
	message = 1000;
	message = message*message;
	message = message*message;
	message = message*message;
	message = message*1000000;
	elgamal.KeyGen((long)100);
	cout << "Prime: " << elgamal.prime << '\n';
	cout << "g: " << elgamal.g << '\n';
	cout << "sKey: " << elgamal.sKey << '\n';
	cout << "pKey: " << elgamal.pKey << '\n';
	
	cipher = elgamal.Encrypt(message);
	cout << cipher.c1 << " " << cipher.c2 << '\n';

	cout << elgamal.Decrypt(cipher) << '\n';
	return 0;
}

