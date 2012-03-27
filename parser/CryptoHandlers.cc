#include <parser/CryptoHandlers.hh>
#include <crypto/ope.hh>
#include <util/util.hh>

using namespace std;
using namespace NTL;

//TODO: this is duplicated in cdb_rewrite
static char *
make_thd_string(const string &s, size_t *lenp = 0)
{
    THD *thd = current_thd;
    assert(thd);

    if (lenp)
        *lenp = s.size();
    return thd->strmake(s.data(), s.size());
}

static string
ItemToString(Item * i) {
    String s;
    String *s0 = i->val_str(&s);
    assert(s0 != NULL);
    return string(s0->ptr(), s0->length());
}

//TODO: remove above newcreatefield
static Create_field*
createFieldHelper(const Create_field *f, int field_length,
		  enum enum_field_types type,
		  CHARSET_INFO * charset = NULL) {
    THD *thd = current_thd;
    Create_field *f0 = f->clone(thd->mem_root);
    if (field_length != -1) {
	f0->length = field_length;
    }
    f0->sql_type = type;
    
    if (charset != NULL) {
	f0->charset = charset;
    } else {
	//encryption is always unsigned
	f0->flags = f0->flags | UNSIGNED_FLAG; 
    }
    return f0;
}

/****************** RND *********************/

RND_int::RND_int(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      bf(key)
{
}


Create_field *
RND_int::newCreateField() {
    return createFieldHelper(cf, ciph_size, MYSQL_TYPE_LONGLONG);
}

//TODO: may want to do more specialized crypto for lengths
Item *
RND_int::encrypt(Item * ptext, uint64_t IV) {
    //TODO: should have encrypt_SEM work for any length
    uint64_t p = static_cast<Item_int *>(ptext)->value;
    uint64_t c = bf.encrypt(p ^ IV);
    return new Item_int((ulonglong) c);
}

Item *
RND_int::decrypt(Item * ctext, uint64_t IV) {
    uint64_t c = static_cast<Item_int*>(ctext)->value;
    uint64_t p = bf.decrypt(c) ^ IV;
    return new Item_int((ulonglong) p);
}


static LEX_STRING n_decRNDInt = {
    (char *) "decrypt_int_sem",
    sizeof("decrypt_int_sem"),
};

static udf_func u_decRNDInt = {
    n_decRNDInt,
    INT_RESULT,
    UDFTYPE_FUNCTION,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0L,
};


Item * 
RND_int::decryptUDF(Item * col, Item * ivcol) {
    cerr << "udf expects key represented in different manner, fix udf";
       
    List<Item> l;
    l.push_back(col);
    l.push_back(new Item_string(make_thd_string(key), key.length(), &my_charset_bin));
    l.push_back(ivcol);
    
    return new Item_func_udf_int(&u_decRNDInt, l);	
}


RND_str::RND_str(Create_field * f, PRNG * key)
    : EncLayer(f),
      rawkey(key->rand_string(key_bytes))
{
    enckey = get_AES_enc_key(rawkey);
    deckey = get_AES_dec_key(rawkey);
}

Create_field *
RND_str::newCreateField() {
//TODO: use more precise sizes and types
    return createFieldHelper(cf, -1, MYSQL_TYPE_BLOB);
}

Item *
RND_str::encrypt(Item * ptext, uint64_t IV) {
    string enc = CryptoManager::encrypt_SEM(
	ItemToString(static_cast<Item_string *>(ptext)),
	enckey, IV);
    return new Item_string(make_thd_string(enc), enc.length(), &my_charset_bin);
}

Item *
RND_str::decrypt(Item * ctext, uint64_t IV) {
    string dec = CryptoManager::decrypt_SEM(
	ItemToString(static_cast<Item_string *>(ctext)),
	deckey, IV);
    return new Item_string(make_thd_string(dec), dec.length(), &my_charset_bin);
}


//TODO; make edb.cc udf naming consistent with these handlers
static LEX_STRING n_decRNDString = {
    (char *) "decrypt_text_sem",
    sizeof("decrypt_text_sem"),
};

static udf_func u_decRNDString = {
    n_decRNDString,
    STRING_RESULT,
    UDFTYPE_FUNCTION,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0L,
};


Item *
RND_str::decryptUDF(Item * col, Item * ivcol) {
    cerr << "udf expects key represented in different manner, fix udf";
       
    List<Item> l;
    l.push_back(col);
    l.push_back(new Item_string(make_thd_string(rawkey), rawkey.length(), &my_charset_bin));
    l.push_back(ivcol);
    
    return new Item_func_udf_str(&u_decRNDString, l);	
}


/********** DET ************************/



DET_int::DET_int(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(bf_key_size)),
      bf(key)
{
}

Create_field *
DET_int::newCreateField() {
    return createFieldHelper(cf, ciph_size, MYSQL_TYPE_LONGLONG);
}

//TODO: may want to do more specialized crypto for lengths
Item *
DET_int::encrypt(Item * ptext, uint64_t IV) {
    return new Item_int((ulonglong) bf.encrypt(static_cast<Item_int *>(ptext)->value));
}

Item *
DET_int::decrypt(Item * ctext, uint64_t IV) {
    return new Item_int((ulonglong) bf.decrypt(static_cast<Item_int*>(ctext)->value));
}


static LEX_STRING n_decDETInt = {
    (char *) "decrypt_int_det",
    sizeof("decrypt_int_det"),
};

static udf_func u_decDETInt = {
    n_decDETInt,
    INT_RESULT,
    UDFTYPE_FUNCTION,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0L,
};


Item *
DET_int::decryptUDF(Item * col, Item * ivcol) {
    cerr << "udf expects key represented in different manner, fix udf";
       
    List<Item> l;
    l.push_back(col);
    l.push_back(new Item_string(make_thd_string(key), key.length(), &my_charset_bin));
    
    return new Item_func_udf_int(&u_decDETInt, l);	
}

DET_str::DET_str(Create_field * f, PRNG * key)
    : EncLayer(f)
{
    rawkey = key->rand_string(key_bytes);
    enckey = get_AES_enc_key(rawkey);
    deckey = get_AES_dec_key(rawkey);
}


Create_field *
DET_str::newCreateField() {
//TODO: use more precise sizes and types
    return createFieldHelper(cf, -1, MYSQL_TYPE_BLOB);
}

Item *
DET_str::encrypt(Item * ptext, uint64_t IV) {
    string enc = encrypt_AES_CMC(
	ItemToString(static_cast<Item_string *>(ptext)),
	enckey, false);
    return new Item_string(make_thd_string(enc), enc.length(), &my_charset_bin);
}

Item *
DET_str::decrypt(Item * ctext, uint64_t IV) {
    string dec = decrypt_AES_CMC(
	ItemToString(static_cast<Item_string *>(ctext)),
	deckey, false);
    return new Item_string(make_thd_string(dec), dec.length(), &my_charset_bin);
}



static LEX_STRING n_decDETStr = {
    (char *) "decrypt_text_det",
    sizeof("decrypt_text_det"),
};

static udf_func u_decDETStr = {
    n_decDETStr,
    STRING_RESULT,
    UDFTYPE_FUNCTION,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0L,
};



Item *
DET_str::decryptUDF(Item * col, Item * ivcol) {
    cerr << "udf expects key represented in different manner, fix udf";
       
    List<Item> l;
    l.push_back(col);
    l.push_back(new Item_string(make_thd_string(rawkey), rawkey.length(), &my_charset_bin));
    
    return new Item_func_udf_str(&u_decDETStr, l);

}

/**************** OPE **************************/

OPE_int::OPE_int(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      ope(key, plain_size * 8, ciph_size * 8)
{
}

Create_field *
OPE_int::newCreateField() {
    return createFieldHelper(cf, -1, MYSQL_TYPE_LONGLONG);
}

Item *
OPE_int::encrypt(Item * ptext, uint64_t IV) {
    ZZ enc = ope.encrypt(to_ZZ((ulong) static_cast<Item_int *>(ptext)->value));
    return new Item_int((ulonglong) trunc_long(enc, 64));
}

Item *
OPE_int::decrypt(Item * ctext, uint64_t IV) {
    ZZ dec = ope.decrypt(to_ZZ((ulong) static_cast<Item_int*>(ctext)->value));
    return new Item_int((ulonglong) trunc_long(dec, 32));
}


OPE_str::OPE_str(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      ope(key, plain_size * 8, ciph_size * 8)
{
}

Create_field *
OPE_str::newCreateField() {
    return createFieldHelper(cf, -1, MYSQL_TYPE_LONGLONG);
}

Item *
OPE_str::encrypt(Item * ptext, uint64_t IV) {
    string ps = ItemToString(ptext);
    if (ps.size() < plain_size)
        ps = string(plain_size - ps.size(), 0) + ps;
    uint32_t pv;
    memcpy(&pv, ps.data(), plain_size);
    ZZ enc = ope.encrypt(to_ZZ(ntohl(pv)));
    return new Item_int((ulonglong) trunc_long(enc, ciph_size));
}

Item *
OPE_str::decrypt(Item * ctext, uint64_t IV) {
    thrower() << "cannot decrypt string from OPE";
}

/**************** HOM ***************************/

HOM::HOM(Create_field * f, PRNG * key)
    : EncLayer(f),
      sk(Paillier_priv::keygen(key, nbits))
{
}

Create_field *
HOM::newCreateField() {
    return createFieldHelper(cf, 2*nbits/8, MYSQL_TYPE_VARCHAR, &my_charset_bin);
}

static ZZ
ItemToZZ(Item * ptext) {
    ulonglong val = ((Item_int*) ptext)->value;
    return to_ZZ((unsigned long)val);
}

static Item *
ZZToItem(const ZZ & val) {
    return new Item_int(to_int(val));
}

Item *
HOM::encrypt(Item * ptext, uint64_t IV) {
    ZZ enc = sk.encrypt(ItemToZZ(ptext));
    return ZZToItem(enc);
}

Item *
HOM::decrypt(Item * ctext, uint64_t IV) {
    ZZ dec = sk.decrypt(ItemToZZ(ctext));
    return ZZToItem(dec);
}


static LEX_STRING n_sum = {
    (char*)"agg_add",
    sizeof("agg_add"),
};

static udf_func u_sum = {
    n_sum,
    STRING_RESULT,
    UDFTYPE_AGGREGATE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0L,
};


Item *
HOM::sumUDF(Item * expr) {
    cerr << "udf expects key represented in different manner, fix udf";
       
    List<Item> l;
    l.push_back(expr);
    for (ZZ i: sk.pubkey()) {
	l.push_back(ZZToItem(i));
    }
    
    return new Item_func_udf_str(&u_sum, l);
}

/******* SEARCH **************************/

Search::Search(Create_field * f, PRNG * key)
    : EncLayer(f)
{
    rawkey = key->rand_string(key_bytes);
    this->key = Binary(key_bytes, (unsigned char *)rawkey.data());
}

Create_field *
Search::newCreateField() {
    return createFieldHelper(cf, -1, MYSQL_TYPE_BLOB);
}


//this function should in fact be provided by the programmer
//currently, we split by whitespaces
// only consider words at least 3 chars in len
// discard not unique objects
static list<Binary> *
tokenize(string text)
{
    static const std::set<char> myDelimsStay = {};
    static const std::set<char> myDelimsGo   = {' ', ',', ';', ':', '.'};
    static const std::set<char> myKeepIntact = {};

    list<string> tokens = parse(text, myDelimsStay, myDelimsGo, myKeepIntact);

    std::set<string> search_tokens;

    list<Binary> * res = new list<Binary>();

    for (list<string>::iterator it = tokens.begin(); it != tokens.end();
         it++) {
        if ((it->length() >= 3) &&
            (search_tokens.find(*it) == search_tokens.end())) {
            string token = toLowerCase(*it);
            search_tokens.insert(token);
            res->push_back(Binary((uint) it->length(),
                                  (unsigned char *) token.data()));
        }
    }

    search_tokens.clear();
    return res;

}

Item *
Search::encrypt(Item * ptext, uint64_t IV) {
    string plainstr = ItemToString(ptext);
    //TODO: remove Binary, string serves this purpose now..
    list<Binary> * tokens = tokenize(plainstr);
    Binary ciph = CryptoManager::encryptSWP(key, *tokens);
    
    return new Item_string((const char *)ciph.content, ciph.len, &my_charset_bin);
}

Item *
Search::decrypt(Item * ctext, uint64_t IV) {
    thrower() << "decryption from SWP not supported \n";
}


static LEX_STRING n_search = {
    (char*)"searchSWP",
    sizeof("searchSWP"),
};

static udf_func u_search = {
    n_search,
    INT_RESULT,
    UDFTYPE_FUNCTION,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0L,
};

Item *
Search::searchUDF(Item * expr) {
    Token t = CryptoManager::token(key, Binary(ItemToString(expr)));
    
    List<Item> l;
    l.push_back(expr);
    l.push_back(new Item_string((const char *)t.ciph.content, t.ciph.len, &my_charset_bin));
    l.push_back(new Item_string((const char *)t.wordKey.content, t.wordKey.len, & my_charset_bin));
    
    return new Item_func_udf_int(&u_sum, l);
}

/************ EncLayer factory creation  ********/

EncLayer *
EncLayerFactory::encLayer(SECLEVEL sl, Create_field * cf, PRNG * key) {
    switch (sl) {
    case SECLEVEL::RND: {
	if (IsMySQLTypeNumeric(cf->sql_type)) {
	    return new RND_int(cf, key);
	} else {
	    return new RND_str(cf, key);
	}
    }
    case SECLEVEL::DET: {
	if (IsMySQLTypeNumeric(cf->sql_type)) {
	    return new DET_int(cf, key);
	} else {
	    return new DET_str(cf, key);
	}
    }
    case SECLEVEL::DETJOIN: {
	return new DETJOIN(cf, key);
    }
    case SECLEVEL::OPE: {
	if (IsMySQLTypeNumeric(cf->sql_type)) {
	    return new OPE_int(cf, key);
	} else {
	    return new OPE_str(cf, key);
	}
    }
    case SECLEVEL::HOM: {
	return new HOM(cf, key);
    }
    case SECLEVEL::SEARCH: {
	return new Search(cf, key);
    }
    default:{
	
    }
    }
    thrower() << "unknown or unimplemented security level \n";
}
