#pragma once

#include <util/util.hh>
#include <crypto/prng.hh>
#include <crypto-old/BasicCrypto.hh>
#include <crypto-old/CryptoManager.hh>
#include <crypto/paillier.hh>

#include <sql_select.h>
#include <sql_delete.h>
#include <sql_insert.h>
#include <sql_update.h>



// An enc layer encrypts and decrypts data for a certain onion layer. It also 
// knows how to transform the data type of some plain data to the data type of
// encrypted data in the DBMS.
//TODO: currently, we have one such object per onion layer per field
// optimize storage by sharing these handlers among objects with same type
//TODO: need to writeup cleanup & destructors

class EncLayer {
public:
    virtual SECLEVEL level() = 0;
    virtual Create_field * newCreateField() = 0;
    
    virtual Item * encrypt(Item * ptext, uint64_t IV = 0) = 0;
    virtual Item * decrypt(Item * ctext, uint64_t IV = 0) = 0;
    virtual Item * decryptUDF(Item * col, Item * ivcol = NULL) {
        thrower() << "decryptUDF not supported";
    }
};


class EncLayerFactory {
public:
    static EncLayer * encLayer(SECLEVEL sl, Create_field * cf, PRNG * key);
};


class RND_int : public EncLayer {
public:
    RND_int(Create_field *, PRNG * key);

    SECLEVEL level() {return SECLEVEL::RND;}
    Create_field * newCreateField();
    
    Item * encrypt(Item * ptext, uint64_t IV);
    Item * decrypt(Item * ctext, uint64_t IV);
    Item * decryptUDF(Item * col, Item * ivcol);

private:
    Create_field * cf;
    std::string key;
    blowfish bf;
    static const int key_bytes = 16;
    
    static const int ciph_size = 8;
};

class RND_str : public EncLayer {
public:
    RND_str(Create_field *, PRNG * key);

    SECLEVEL level() {return SECLEVEL::RND;}
    Create_field * newCreateField();
    
    Item * encrypt(Item * ptext, uint64_t IV);
    Item * decrypt(Item * ctext, uint64_t IV);
    Item * decryptUDF(Item * col, Item * ivcol);

private:
    Create_field * cf;
    std::string rawkey;
    static const int key_bytes = 16;
    AES_KEY * enckey;
    AES_KEY * deckey;
};

class DET_int : public EncLayer {
public:
    DET_int(Create_field *, PRNG * key);

    SECLEVEL level() {return SECLEVEL::DET;}
    Create_field * newCreateField();
    
    Item * encrypt(Item * ptext, uint64_t IV = 0);
    Item * decrypt(Item * ctext, uint64_t IV = 0);
    Item * decryptUDF(Item * col, Item * ivcol = NULL);

private:
    Create_field * cf;
    std::string key;
    blowfish bf;
    static const int bf_key_size = 16;
    static const int ciph_size = 8;
};


class DET_str : public EncLayer {
public:
    DET_str(Create_field *, PRNG * key);

    SECLEVEL level() {return SECLEVEL::DET;}
    Create_field * newCreateField();
    
    Item * encrypt(Item * p, uint64_t IV = 0);
    Item * decrypt(Item * c, uint64_t IV = 0);
    Item * decryptUDF(Item * col, Item * = NULL);

private:
    Create_field * cf;
    std::string rawkey;
    static const int key_bytes = 16;
    AES_KEY * enckey;
    AES_KEY * deckey;
};



class OPE_int : public EncLayer {
public:
    OPE_int(Create_field *, PRNG * key);

    SECLEVEL level() {return SECLEVEL::OPE;}
    Create_field * newCreateField();
    
    Item * encrypt(Item * p, uint64_t IV);
    Item * decrypt(Item * c, uint64_t IV);

private:
    Create_field * cf;
    std::string rawkey;
    OPE * key;
    static const int key_bytes = 16;
    static const int plain_size = 4;
    static const int ciph_size = 8;
};


class OPE_str : public EncLayer {
public:
    OPE_str(Create_field *, PRNG * key);

    SECLEVEL level() {return SECLEVEL::OPE;}
    Create_field * newCreateField();
    
    Item * encrypt(Item * p, uint64_t IV = 0);
    Item * decrypt(Item * c, uint64_t IV = 0)__attribute__((noreturn));
  
private:
    Create_field * cf;
    std::string rawkey;
    OPE * key;
    static const int key_bytes = 16;
    static const int plain_size = 4;
    static const int ciph_size = 8;
};


class HOM : public EncLayer {
public:
    HOM(Create_field * cf, PRNG * key);

    SECLEVEL level() {return SECLEVEL::HOM;}
    Create_field * newCreateField();

    Item * encrypt(Item * p, uint64_t IV = 0);
    Item * decrypt(Item * c, uint64_t IV = 0);

    //expr is the expression (e.g. a field) over which to sum
    Item * sumUDF(Item * expr);
    
private:
    Create_field * cf;
    static const uint nbits = 1024;
    Paillier_priv sk;
};

class Search : public EncLayer {
public:
    Search(Create_field * cf, PRNG * key);

    SECLEVEL level() {return SECLEVEL::SEARCH;}
    Create_field * newCreateField();

    Item * encrypt(Item * ptext, uint64_t IV = 0);
    Item * decrypt(Item * ctext, uint64_t IV = 0)__attribute__((noreturn));

    //expr is the expression (e.g. a field) over which to sum
    Item * searchUDF(Item * expr);
    
private:
    Create_field * cf;
    static const uint key_bytes = 16;
    std::string rawkey;
    Binary key;
};
