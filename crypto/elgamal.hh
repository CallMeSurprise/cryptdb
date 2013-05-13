#pragma once

#include <list>
#include <vector>
#include <NTL/ZZ.h>
#include <crypto/prng.hh>

struct elGamalCipher{
	NTL::ZZ c1, c2;
};
typedef struct elGamalCipher ElGamalCipher;

class ElGamal {
	public:
		ElGamal(const std::vector<NTL::ZZ> &key);
		std::vector<NTL::ZZ> pubkey() const { return { pK, q, g }; }
		NTL::ZZ hompubkey() const { return q; } 
		
		ElGamalCipher encrypt(const NTL::ZZ &m);
		NTL::ZZ decrypt(const ElGamalCipher &c);
		NTL::ZZ mul(const NTL::ZZ &c0, const NTL::ZZ &c1) const;
		
		static std::vector<NTL::ZZ> keygen(PRNG*, long len = 384, uint abits = 256);
		void rand_gen(size_t niter = 100, size_t nmax = 1000);

	protected:
		std::list<NTL::ZZ> rqueue; //pre-computed randomness

	private:
		NTL::ZZ pK; //public key g^x
		NTL::ZZ sK; //private key x
		NTL::ZZ q; //prime
		NTL::ZZ g; //generator
};

