#include <crypto/elgamal.hh>
#include <iostream>
#include <NTL/ZZ.h>
#include <crypto/prng.hh>

using namespace std;
using namespace NTL;

ElGamal::ElGamal(const std::vector<ZZ> &key)
	: pK(key[0]), q(key[1]), g(key[2]), sK(key[3])
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
        ZZ r = RandomLen_ZZ(1024) % q; //sorry for magic numbers will fix
        ZZ rq = PowerMod(g, q*r, q);
        rqueue.push_back(rq);
    }
}

vector<ZZ> ElGamal::keygen(PRNG* rng, long len, uint abits) {
	//generate a safe prime
	ZZ p = GenGermainPrime_ZZ(len, 80);
	ZZ prime = 2*p + 1; 
	
	//pick a generator in Z_q
	ZZ gen = rng->rand_zz_nbits(abits);
	
	while (!gen_check(p, prime, gen)) {
		gen = rng->rand_zz_nbits(abits);
	}
	
	ZZ x = rng->rand_zz_nbits(abits); //secret key
 
	ZZ h = PowerMod(gen, x, prime); // Calculates g^x (mod prime)
	return { h, prime, gen, x };
}

/*
* Check if gen is a generator mod q = 2p+1
*/
bool ElGamal::gen_check(ZZ p, ZZ q, ZZ gen) {
	if (PowerMod(gen, p, q) == 1) {
		return false;
	} else if(PowerMod(gen, 2, q) == 1) {
		return false;
	} 
	return true; 
}

ZZ ElGamal::encrypt(const ZZ &m){
	ZZ c1, c2;
	unsigned char c1p[96]; //768 bits = max size of q
	unsigned char c2p[96]; 

	ZZ k = RandomBnd(q); //random number in Z_q

	PowerMod(c1,g,k,q);		// c1 = g^k %q
	PowerMod(c2,pK,k,q);	// c2 = pK^k %q
	MulMod(c2,m,c2,q);	// c2 = m*pK^k %q

	BytesFromZZ(c1p, c1, 96); 
	BytesFromZZ(c2p, c2, 96);

	return ZZFromBytes(c1p, 192); //turn concat of arrays into ZZ
}

ZZ ElGamal::decrypt(const ZZ &c){
	unsigned char cp[192];
	
	BytesFromZZ(cp, c, 192); 

	ZZ c1 = ZZFromBytes(cp, 96);
	ZZ c2 = ZZFromBytes((cp+96), 96); 
	
	ZZ s = PowerMod(c1,sK,q);
	InvMod(s,s,q);
	ZZ ret = MulMod(c2,s,q);
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
