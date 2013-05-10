/*
 * There are three or four incompatible memory allocators:
 *
 *   palloc / pfree (Postgres-specific)
 *   malloc / free
 *   new / delete
 *   new[] / delete[]
 *
 * The Postgres versions of the UDFs likely do not keep track of which
 * allocator is used in each case.  They might not free memory at all
 * in some cases, and might free memory with a different allocator than
 * the one used to initially allocate it.  Beware.
 *
 * The MySQL versions of the UDFs are more likely to get this right.
 */

#define DEBUG 1

#include <crypto/BasicCrypto.hh> 
#include <crypto/blowfish.hh>
#include <crypto/SWPSearch.hh>
#include <crypto/paillier.hh>
#include <util/params.hh>
#include <util/util.hh>

using namespace std;
using namespace NTL;

extern "C" {


typedef unsigned long long ulonglong;
typedef long long longlong;
#include <mysql.h>
#include <ctype.h>

my_bool  decrypt_int_sem_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
ulonglong decrypt_int_sem(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                         char *error);

    
my_bool  decrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
ulonglong decrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                         char *error);

my_bool  decrypt_text_sem_init(UDF_INIT *initid, UDF_ARGS *args,
                               char *message);
void     decrypt_text_sem_deinit(UDF_INIT *initid);
char *   decrypt_text_sem(UDF_INIT *initid, UDF_ARGS *args, char *result,
                          unsigned long *length, char *is_null, char *error);

my_bool  encrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
ulonglong encrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                         char *error);

my_bool  decrypt_text_det_init(UDF_INIT *initid, UDF_ARGS *args,
                               char *message);
void     decrypt_text_det_deinit(UDF_INIT *initid);
char *   decrypt_text_det(UDF_INIT *initid, UDF_ARGS *args, char *result,
                          unsigned long *length, char *is_null, char *error);

my_bool  search_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
ulonglong search(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);

my_bool  searchSWP_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void     searchSWP_deinit(UDF_INIT *initid);
ulonglong searchSWP(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                   char *error);


my_bool  agg_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void     agg_deinit(UDF_INIT *initid);
void     agg_clear(UDF_INIT *initid, char *is_null, char *error);
my_bool  agg_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);
char *   agg(UDF_INIT *initid, UDF_ARGS *args, char *result,
             unsigned long *length, char *is_null, char *error);

void     func_add_set_deinit(UDF_INIT *initid);
char *   func_add_set(UDF_INIT *initid, UDF_ARGS *args, char *result,
                      unsigned long *length, char *is_null, char *error);

// product UDF 
void     prod_deinit(UDF_INIT *initid);
char *   prod(UDF_INIT *initid, UDF_ARGS *args, char *result,
                      unsigned long *length, char *is_null, char *error);
}

static void __attribute__((unused))
log(string s)
{
    /* Writes to the server's error log */
    fprintf(stderr, "%s\n", s.c_str());
}


static string
decrypt_SEM(unsigned char *eValueBytes, uint64_t eValueLen,
            AES_KEY * aesKey, uint64_t salt)
{
    string c((char *) eValueBytes, (unsigned int) eValueLen);
    return decrypt_AES_CBC(c, aesKey, BytesFromInt(salt, SALT_LEN_BYTES), false);
}


static list<string> *
split(const string & s, unsigned int plen)
{
    unsigned int len = s.length();
    if (len % plen != 0) {
        thrower() << "split receives invalid input";
    }

    unsigned int num = len / plen;
    list<string> * res = new list<string>();

    for (unsigned int i = 0; i < num; i++) {
        res->push_back(s.substr(i*plen, plen));
    }

    return res;
}


static bool
searchExists(const Token & token, const string & overall_ciph)
{
    auto l = split(overall_ciph, SWPCiphSize);
    bool r = SWP::searchExists(token, *l);
    delete l;
    return r;
}


static bool
search(const Token & token, const string & overall_ciph)
{
   return searchExists(token, overall_ciph);
}


#if MYSQL_S
#define ARGS args

static uint64_t
getui(UDF_ARGS * args, int i)
{
    return (uint64_t) (*((ulonglong *) args->args[i]));
}

static char *
getba(UDF_ARGS * args, int i, uint64_t &len)
{
    len = args->lengths[i];
    return args->args[i];
}

#else

#define ARGS PG_FUNCTION_ARGS

static uint64_t
getui(ARGS, int i)
{
    return PG_GETARG_INT64(i);
}

static unsigned char
getb(ARGS, int i)
{
    return (unsigned char)PG_GETARG_INT32(i);
}

static unsigned char *
getba(ARGS, int i, unsigned int & len)
{
    bytea * eValue = PG_GETARG_BYTEA_P(i);

    len = VARSIZE(eValue) - VARHDRSZ;
    unsigned char * eValueBytes = new unsigned char[len];
    memcpy(eValueBytes, VARDATA(eValue), len);
    return eValueBytes;
}

#endif

extern "C" {

#if MYSQL_S
my_bool
decrypt_int_sem_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

ulonglong
decrypt_int_sem(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else /*postgres*/
Datum
decrypt_int_sem(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValue = getui(ARGS, 0);

    uint64_t keyLen;
    char * keyBytes = getba(args, 1, keyLen);
    string key = string(keyBytes, keyLen);
    
    uint64_t salt = getui(args, 2);

    blowfish bf(key);
    uint64_t value = bf.decrypt(eValue) ^ salt;

    //cerr << "udf: encVal " << eValue << " key " << (int)key[0] << " " << (int)key[1] << " " << (int) key[3]  << " salt " << salt  << " obtains: " << value << " and cast to ulonglong " << (ulonglong) value << "\n";

   
#if MYSQL_S
     return (ulonglong) value;
#else /* postgres */
    PG_RETURN_INT64(value);
#endif
}


    
#if MYSQL_S
my_bool
decrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

ulonglong
decrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else /* postgres */
Datum
decrypt_int_det(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValue = getui(ARGS, 0);

    uint64_t keyLen;
    char * keyBytes = getba(args, 1, keyLen);
    string key = string(keyBytes, keyLen);
   
    blowfish bf(key);
    uint64_t value = bf.decrypt(eValue);

#if MYSQL_S
    return (ulonglong) value;
#else /* postgres */
    PG_RETURN_INT64(value);
#endif

}



my_bool
decrypt_text_sem_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

void
decrypt_text_sem_deinit(UDF_INIT *initid)
{
    /*
     * in mysql-server/sql/item_func.cc, udf_handler::fix_fields
     * initializes initid.ptr=0 for us.
     */
    if (initid->ptr)
        delete[] initid->ptr;
}

char *
decrypt_text_sem(UDF_INIT *initid, UDF_ARGS *args,
                 char *result, unsigned long *length,
                 char *is_null, char *error) {
    uint64_t eValueLen;
    char *eValueBytes = getba(args, 0, eValueLen);

    uint64_t keyLen;
    char * keyBytes = getba(args, 1, keyLen);
    string key = string(keyBytes, keyLen);
    
    uint64_t salt = getui(ARGS, 2);

    AES_KEY *aesKey = get_AES_dec_key(key);
          
   string value = decrypt_SEM((unsigned char *)eValueBytes, eValueLen, aesKey, salt);
   delete aesKey;
    
    char * res = new char[value.length()];
    initid->ptr = res;
    memcpy(res, value.data(), value.length());
    *length =  value.length();
  
    return (char*) initid->ptr;
}
    

    
#if MYSQL_S
my_bool
encrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

ulonglong
encrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else /* postgres */
Datum
decrypt_int_det(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValue = getui(ARGS, 0);

    uint64_t keyLen;
    char * keyBytes = getba(args, 1, keyLen);
    string key = string(keyBytes, keyLen);
   
    blowfish bf(key);
    uint64_t value = bf.encrypt(eValue);

#if MYSQL_S
    return (ulonglong) value;
#else /* postgres */
    PG_RETURN_INT64(value);
#endif

}


#if MYSQL_S
my_bool
decrypt_text_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

void
decrypt_text_det_deinit(UDF_INIT *initid)
{
    /*
     * in mysql-server/sql/item_func.cc, udf_handler::fix_fields
     * initializes initid.ptr=0 for us.
     */
    if (initid->ptr)
        delete[] initid->ptr;
}

char *
decrypt_text_det(UDF_INIT *initid, UDF_ARGS *args,
                 char *result, unsigned long *length,
                 char *is_null, char *error)
#else /* postgres */
Datum
decrypt_text_det(PG_FUNCTION_ARGS)
#endif
{
     uint64_t eValueLen;
    char *eValueBytes = getba(args, 0, eValueLen);

    uint64_t keyLen;
    char *keyBytes = getba(args, 1, keyLen);
    string key = string(keyBytes, keyLen);
    
    AES_KEY * aesKey = get_AES_dec_key(key);
    string value = decrypt_AES_CMC(string(eValueBytes, (unsigned int)eValueLen), aesKey, false);
    delete aesKey;

#if MYSQL_S
    char * res = new char[value.length()];
    initid->ptr = res;
    memcpy(res, value.data(), value.length());
    *length =  value.length();
    return (char*) initid->ptr;
#else
    bytea * res = (bytea *) palloc(eValueLen+VARHDRSZ);
    SET_VARSIZE(res, eValueLen+VARHDRSZ);
    memcpy(VARDATA(res), value, eValueLen);
    PG_RETURN_BYTEA_P(res);
#endif

}

/*
 * given field of the form:   len1 word1 len2 word2 len3 word3 ...,
 * where each len is the length of the following "word",
 * search for word which is of the form len word_body where len is
 * the length of the word body
 */

    
#if MYSQL_S
my_bool
search_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}


ulonglong
search(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else
Datum
search(PG_FUNCTION_ARGS)
#endif
{
    uint64_t wordLen;
    char * word = (char *)getba(ARGS, 0, wordLen);
    if (wordLen != (unsigned int)word[0]) {
        cerr << "ERR: wordLen is not equal to fist byte of word!!! ";
    }
    word = word + 1;     // +1 skips over the length field
    //cerr << "given expr to search for has " << wordLen << " length \n";

    uint64_t fieldLen;
    char *field = (char *) getba(ARGS, 1, fieldLen);

    //cerr << "searching for "; myPrint((unsigned char *)word, wordLen); cerr
    // << " in field "; myPrint((unsigned char *)field, fieldLen); cerr <<
    // "\n";

    unsigned int i = 0;
    while (i < fieldLen) {
        unsigned int currLen = (unsigned int)field[i];
        if (currLen != wordLen) {
            i = i + currLen+1;
            continue;
        }

        //need to compare
        unsigned int j;
        for (j = 0; j < currLen; j++) {
            if (field[i+j+1] != word[j]) {
                break;
            }
        }
        if (j == currLen) {
#if MYSQL_S
            return 1;
#else
            PG_RETURN_BOOL(true);
#endif
        }
        i = i + currLen + 1;
    }

#if MYSQL_S
    return 0;
#else
    PG_RETURN_BOOL(true);
#endif
}

#if MYSQL_S

//TODO: write a version of search for postgres

my_bool
searchSWP_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    Token * t = new Token();

    uint64_t ciphLen;
    char *ciph = getba(args, 1, ciphLen);

    uint64_t wordKeyLen;
    char *wordKey = getba(args, 2, wordKeyLen);

    t->ciph = string(ciph, ciphLen);
    t->wordKey = string(wordKey, wordKeyLen);

    initid->ptr = (char *) t;

    return 0;
}

void
searchSWP_deinit(UDF_INIT *initid)
{
    Token *t = (Token *) initid->ptr;
    delete t;
}

ulonglong
searchSWP(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    uint64_t allciphLen;
    char * allciph = getba(ARGS, 0, allciphLen);
    string overallciph = string(allciph, allciphLen);

    Token * t = (Token *) initid->ptr;

    return search(*t, overallciph);
}

#endif


   
    
struct agg_state {
    ZZ sum;
    ZZ n2;
    bool n2_set;
    void *rbuf;
};

my_bool
agg_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    cerr << "in agg_init \n";
    agg_state *as = new agg_state();
    as->rbuf = malloc(Paillier_len_bytes);
    initid->ptr = (char *) as;
    cerr << "returning from agg_init \n";
    return 0;
}

void
agg_deinit(UDF_INIT *initid)
{
    agg_state *as = (agg_state *) initid->ptr;
    free(as->rbuf);
    delete as;
}

void
agg_clear(UDF_INIT *initid, char *is_null, char *error)
{
    agg_state *as = (agg_state *) initid->ptr;
    as->sum = to_ZZ(1);
    as->n2_set = 0;
}

//args will be element to add, constant N2
my_bool
agg_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    //cerr << "in agg_add \n";
    agg_state *as = (agg_state *) initid->ptr;
    if (!as->n2_set) {
	//cerr << "n2 length is " << args->lengths[1] << "\n";
	//cerr << "n2 first byte is " << (int)args->args[1][0] << "\n";
	ZZFromBytes(as->n2, (const uint8_t *) args->args[1],
                        args->lengths[1]);
	//cerr << "n2 is " << as->n2 << "\n";
        as->n2_set = 1;
    }
  
    ZZ e;
    ZZFromBytes(e, (const uint8_t *) args->args[0], args->lengths[0]);

    //cerr << "element to add " << e << "\n";
    MulMod(as->sum, as->sum, e, as->n2);
    //cerr << "sum so far " << as->sum << "\n";
    return true;
}

char *
agg(UDF_INIT *initid, UDF_ARGS *args, char *result,
    unsigned long *length, char *is_null, char *error)
{
    agg_state *as = (agg_state *) initid->ptr;
    BytesFromZZ((uint8_t *) as->rbuf, as->sum,
                 Paillier_len_bytes);
    *length = Paillier_len_bytes;
    return (char *) as->rbuf;
}

// for update with increment

void
func_add_set_deinit(UDF_INIT *initid)
{
    if (initid->ptr)
        free(initid->ptr);
}


char *
func_add_set(UDF_INIT *initid, UDF_ARGS *args,
             char *result, unsigned long *length,
             char *is_null, char *error)
{
    if (initid->ptr)
        free(initid->ptr);

    uint64_t n2len = args->lengths[2];
    
    ZZ field, val, n2;
    ZZFromBytes(field, (const uint8_t *) args->args[0], args->lengths[0]);
    ZZFromBytes(val, (const uint8_t *) args->args[1], args->lengths[1]);
    ZZFromBytes(n2, (const uint8_t *) args->args[2], args->lengths[2]);

    ZZ res;
    MulMod(res, field, val, n2);

    void *rbuf = malloc((size_t)n2len);
    initid->ptr = (char *) rbuf;
    BytesFromZZ((uint8_t *) rbuf, res, (size_t)n2len);

    *length = (long unsigned int) n2len;
    return initid->ptr;
}

// For product of column with value
void
prod_deinit(UDF_INIT *initid)
{
    if (initid->ptr)
        free(initid->ptr);
}

char *
prod(UDF_INIT *initid, UDF_ARGS *args,
             char *result, unsigned long *length,
             char *is_null, char *error)
{
    if (initid->ptr)
        free(initid->ptr);

    uint64_t n2len = args->lengths[2];
    ZZ field, val, n2;
    ZZFromBytes(field, (const uint8_t *) args->args[0], args->lengths[0]);
    ZZFromBytes(val, (const uint8_t *) args->args[1], args->lengths[1]);
    ZZFromBytes(n2, (const uint8_t *) args->args[2], args->lengths[2]);

    ZZ res;
    MulMod(res, field, val, n2);

    void *rbuf = malloc((size_t)n2len);
    initid->ptr = (char *) rbuf;
    BytesFromZZ((uint8_t *) rbuf, res, (size_t)n2len);

    *length = (long unsigned int) n2len;
    return initid->ptr;
}

    
} /* extern "C" */
