#pragma once

#include <list>
#include <vector>
#include <NTL/ZZ.h>
#include <crypto/prng.hh>

using namespace std;
using namespace NTL;

class ElGamal {
	public:
		ElGamal(const vector<ZZ> &key);
		ZZ hompubkey() const { return q; } 
		
		ZZ encrypt(const ZZ &m);
		ZZ decrypt(const ZZ &c);
		
		static vector<ZZ> keygen(PRNG* rng, long len = 766, uint abits = 256);
		void rand_gen(size_t niter = 100, size_t nmax = 1000);

		static bool gen_check(ZZ p, ZZ q, ZZ gen);

		static ZZ mul(ZZ a, ZZ b, ZZ q);

	protected:
		list<ZZ> rqueue; //pre-computed randomness

	private:
		ZZ pK; //public key g^x
		ZZ q; //prime
		ZZ g; //generator
		ZZ sK; //private key x
};

