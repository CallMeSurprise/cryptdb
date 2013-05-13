#include <crypto/elgamal.hh>
#include <iostream>
#include <NTL/ZZ.h>
#include <crypto/prng.hh>

using namespace std;
using namespace NTL;

ElGamal::ElGamal(const std::vector<NTL::ZZ> &key)
	: pK(key[0]), q(key[1]), g(key[2]),
	  sK(key[3])
{
}

void
ElGamal::rand_gen(size_t niter, size_t nmax)
{
    if (rqueue.size() >= nmax)
        niter = 0;
    else
        niter = min(niter, nmax - rqueue.size());

    for (uint i = 0; i < niter; i++) {
        ZZ r = RandomLen_ZZ(nbits) % n;
        ZZ rn = PowerMod(g, n*r, n2);
        rqueue.push_back(rn);
    }
}

std::vector<NTL::ZZ> ElGamal::keygen(PRNG* rng, long len, uint nbits) {
	//generate a safe prime
	ZZ p = GenGermainPrime_ZZ(long l, long err = 80);
	ZZ q = 2*p + 1; 
	
	//pick a generator in Z_q
	ZZ gen = rng->rand_zz_nbits(abits);
	
	while (!genCheck(p, q, gen)) {
		gen = rng->rand_zz_nbits(abits);
	}
	
	ZZ x = rng->rand_zz_nbits(abits); //secret key
 
	ZZ h = PowerMod(g, sK, q); // Calculates g^x (mod prime)
	return { h, prime, gen, x };
}

/*
* Check if gen is a generator mod q = 2p+1
*/
bool genCheck(ZZ p, ZZ q, ZZ gen) {
	if (PowerMod(gen, p, q) == 1) {
		return false;
	} else if(PowerMod(gen, 2, q) == 1) {
		return false;
	} 
	return true; 
}

ElGamalCipher ElGamal::encrypt(ZZ m){
	ElGamalCipher cipher;
	ZZ k = RandomBnd(prime);		// sKey random number in [0,prime-1] NTL LIBRARY
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
/* ONLY FOR TESTING
int main(){
	ElGamal elgamal;
	ElGamalCipher cipher;
	urandom u;
	ZZ message;

	elgamal.KeyGen(&u,1000);

	message = 1000;
	message = message*message;
	message = message*message;
	message = message*message;
	message = message*1000000;
	cout << "Prime: " << elgamal.prime << '\n';
	cout << "g: " << elgamal.g << '\n';
	cout << "sKey: " << elgamal.sKey << '\n';
	cout << "pKey: " << elgamal.pKey << '\n';
	
	cipher = elgamal.Encrypt(message);
	cout << cipher.c1 << " " << cipher.c2 << '\n';

	cout << elgamal.Decrypt(cipher) << '\n';
	return 0;
}
*/
