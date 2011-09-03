#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <util/errstream.hh>

class PRNG {
 public:
    template<class T>
    T rand() {
        T v;
        rand_bytes(sizeof(T), (uint8_t*) &v);
        return v;
    }

    std::string rand_string(size_t nbytes) {
        std::string s;
        s.resize(nbytes);
        rand_bytes(nbytes, (uint8_t*) &s[0]);
        return s;
    }

    template<class T>
    std::vector<T> rand_vec(size_t nelem) {
        std::vector<T> buf(nelem);
        rand_bytes(nelem * sizeof(T), (uint8_t*) &buf[0]);
        return buf;
    }

    virtual ~PRNG() {}
    virtual void rand_bytes(size_t nbytes, uint8_t *buf) = 0;
    virtual void seed_bytes(size_t nbytes, uint8_t *buf) {
        thrower() << "seed not implemented";
    }
};

class urandom : public PRNG {
 public:
    urandom();
    virtual ~urandom() {}
    virtual void rand_bytes(size_t nbytes, uint8_t *buf);
    virtual void seed_bytes(size_t nbytes, uint8_t *buf);

 private:
    std::fstream f;
};

template<class StreamCipher>
class streamrng : public PRNG {
 public:
    streamrng(const std::string &key) : c(key) {}
    virtual void rand_bytes(size_t nbytes, uint8_t *buf) {
        for (size_t i = 0; i < nbytes; i++)
            buf[i] = c.getbyte();
    }

 private:
    StreamCipher c;
};
