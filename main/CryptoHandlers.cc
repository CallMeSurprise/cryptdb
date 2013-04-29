#include <main/CryptoHandlers.hh>
#include <crypto/ope.hh>
#include <crypto/BasicCrypto.hh>
#include <crypto/SWPSearch.hh> 
#include <util/util.hh>
#include <util/cryptdb_log.hh>

#define LEXSTRING(cstr) { (char*) cstr, sizeof(cstr) }


using namespace std;
using namespace NTL;

//TODO: remove above newcreatefield
static Create_field*
createFieldHelper(const Create_field *f, int field_length,
		  enum enum_field_types type, string anonname = "",
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

    if (anonname.size() > 0) {
        f0->field_name = make_thd_string(anonname);
    }
    
    return f0;
    
}

static Item *
get_key_item(const string & key) {
    Item_string * keyI = new Item_string(make_thd_string(key),
					 key.length(), &my_charset_bin);
    keyI->name = NULL; // no alias
    return keyI;
}

// ElGamal

ElGamal::ElGamal(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      bf(key)
{
}


Create_field *
ElGamal::newCreateField(string anonname) {
    return createFieldHelper(cf, ciph_size, MYSQL_TYPE_LONGLONG, anonname);
}

Item *
ElGamal::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    uint64_t p = static_cast<Item_int *>(ptext)->value;
    LOG(encl) << "ElGamal encrypt " << p << " IV " << IV;
    return new Item_int((ulonglong) p);
}

Item *
ElGamal::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    uint64_t c = static_cast<Item_int*>(ctext)->value;
    LOG(encl) << "RND_int decrypt " << c << " IV " << IV;
    return new Item_int((ulonglong) c);
}

void
ElGamal::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = k;
    bf = blowfish(key);
}

//if we're using MultiPrinc, we don't want to keep a copy of a key around
void
ElGamal::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = "";
    //TODO: unset blowfish
}

/****************** RND *********************/

RND_int::RND_int(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      bf(key)
{
    setKey(prng->rand_string(key_bytes));
}


Create_field *
RND_int::newCreateField(string anonname) {
    return createFieldHelper(cf, ciph_size, MYSQL_TYPE_LONGLONG, anonname);
}

void
RND_int::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = k;
    bf = blowfish(key);
}

//if we're using MultiPrinc, we don't want to keep a copy of a key around
void
RND_int::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = "";
    //TODO: unset blowfish
}

//TODO: may want to do more specialized crypto for lengths
Item *
RND_int::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    //TODO: should have encrypt_SEM work for any length
    uint64_t p = static_cast<Item_int *>(ptext)->value;
    uint64_t c = bf.encrypt(p ^ IV);
    LOG(encl) << "RND_int encrypt " << p << " IV " << IV << "-->" << c;
    unSetKey(k);
    return new Item_int((ulonglong) c);
}

Item *
RND_int::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    uint64_t c = static_cast<Item_int*>(ctext)->value;
    uint64_t p = bf.decrypt(c) ^ IV;
    LOG(encl) << "RND_int decrypt " << c << " IV " << IV << " --> " << p;
    unSetKey(k);
    return new Item_int((ulonglong) p);
}

static udf_func u_decRNDInt = {
    LEXSTRING("decrypt_int_sem"),
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
    List<Item> l;
    l.push_back(col);
    
    l.push_back(get_key_item(key));
    
    l.push_back(ivcol);
    
    Item * udfdec = new Item_func_udf_int(&u_decRNDInt, l);
    udfdec->name = NULL; //no alias

    //add encompassing CAST for unsigned
    Item * udf = new Item_func_unsigned(udfdec);
    udf->name = NULL;

    return udf;
}


RND_str::RND_str(Create_field * f, PRNG * key)
    : EncLayer(f)
{
    setKey(key->rand_string(key_bytes));
}

Create_field *
RND_str::newCreateField(string anonname) {
//TODO: use more precise sizes and types
    return createFieldHelper(cf, -1, MYSQL_TYPE_BLOB, anonname, &my_charset_bin);
}

void
RND_str::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    rawkey = k;
    enckey = get_AES_enc_key(rawkey);
    deckey = get_AES_dec_key(rawkey);
}

void
RND_str::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    rawkey = "";
    enckey = NULL;
    deckey = NULL;
}

Item *
RND_str::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    string enc = encrypt_AES_CBC(
                 ItemToString(ptext),
                 enckey,
		 BytesFromInt(IV, SALT_LEN_BYTES),
		 false);
    LOG(encl) << "RND_str encrypt " << ItemToString(ptext) << " IV " << IV << "--->"
	      << "len of enc " << enc.length() << " enc " << enc;
    unSetKey(k);
    return new Item_string(make_thd_string(enc), enc.length(), &my_charset_bin);
}

Item *
RND_str::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    string dec = decrypt_AES_CBC(
	ItemToString(ctext),
	deckey,
	BytesFromInt(IV, SALT_LEN_BYTES),
	false);
    LOG(encl) << "RND_str decrypt " << ItemToString(ctext) << " IV " << IV << "-->"
	      << "len of dec " << dec.length() << " dec: " << dec;
    unSetKey(k);
    return new Item_string(make_thd_string(dec), dec.length(), &my_charset_bin);
}


//TODO; make edb.cc udf naming consistent with these handlers
static udf_func u_decRNDString = {
    LEXSTRING("decrypt_text_sem"),
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
    List<Item> l;
    l.push_back(col);
    l.push_back(get_key_item(rawkey));
    l.push_back(ivcol);
    
    return new Item_func_udf_str(&u_decRNDString, l);	
}


/********** DET ************************/



DET_int::DET_int(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(bf_key_size)),
      bf(key)
{
    setKey(key);
}

Create_field *
DET_int::newCreateField(string anonname) {
    return createFieldHelper(cf, ciph_size, MYSQL_TYPE_LONGLONG, anonname);
}

void
DET_int::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = k;
    bf = blowfish(key);
}

void
DET_int::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = "";
    //TODO: unset blowfish
}
 
//TODO: may want to do more specialized crypto for lengths
Item *
DET_int::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    ulonglong val = static_cast<Item_int *>(ptext)->value;
    ulonglong res = (ulonglong) bf.encrypt(val);
    LOG(encl) << "DET_int encrypt " << val << "--->" << res;
    unSetKey(k);
    return new Item_int(res);
}

Item *
DET_int::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    ulonglong val = static_cast<Item_int*>(ctext)->value;
    ulonglong res = (ulonglong) bf.decrypt(val);
    LOG(encl) << "DET_int decrypt " << val << "-->" << res;
    Item * ni = new Item_int(res);
    unSetKey(k);
    return ni;
}


static udf_func u_decDETInt = {
    LEXSTRING("decrypt_int_det"),
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
    List<Item> l;
    l.push_back(col);

    l.push_back(get_key_item(key));
    
    Item * udfdec = new Item_func_udf_int(&u_decDETInt, l);
    udfdec->name = NULL;
    
    //add encompassing CAST for unsigned
    Item * udf = new Item_func_unsigned(udfdec);
    udf->name = NULL;

    return udf;
}

DET_str::DET_str(Create_field * f, PRNG * key)
    : EncLayer(f)
{
    setKey(key->rand_string(key_bytes));
}


Create_field *
DET_str::newCreateField(string anonname) {
//TODO: use more precise sizes and types
    return createFieldHelper(cf, -1, MYSQL_TYPE_BLOB, anonname, &my_charset_bin);
}

void
DET_str::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    rawkey = k;
    enckey = get_AES_enc_key(rawkey);
    deckey = get_AES_dec_key(rawkey);
}

void
DET_str::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    rawkey = "";
    enckey = NULL;
    deckey = NULL;
}

Item *
DET_str::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    string plain =  ItemToString(ptext);
    string enc = encrypt_AES_CMC(plain,enckey, true);
    LOG(encl) << " DET_str encrypt " << plain  << " IV " << IV << " ---> "
	      << " enc len " << enc.length() << " enc " << enc;
    unSetKey(k);
    return new Item_string(make_thd_string(enc), enc.length(), &my_charset_bin);
}

Item *
DET_str::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    string enc = ItemToString(ctext);
    string dec = decrypt_AES_CMC(enc, deckey, true);
    LOG(encl) << " DET_str decrypt enc len " << enc.length() << " enc " << enc
	      << " IV " << IV << " ---> " << " dec len " << dec.length() << " dec " << dec;
    unSetKey(k);
    return new Item_string(make_thd_string(dec), dec.length(), &my_charset_bin);
}

static udf_func u_decDETStr = {
    LEXSTRING("decrypt_text_det"),
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
    List<Item> l;
    l.push_back(col);
    l.push_back(get_key_item(rawkey));
    return new Item_func_udf_str(&u_decDETStr, l);

}

/*************** DETJOIN *********************/
/*
Item *
DETJOIN::encrypt(Item * p, uint64_t IV, const string &k) {
    return p->clone_item();
}

Item *
DETJOIN::decrypt(Item * c, uint64_t IV, const string &k) {
    return c->clone_item();
}
*/
/**************** OPE **************************/

OPE_int::OPE_int(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      ope(key, plain_size*8, ciph_size*8)
{
    setKey(prng->rand_string(key_bytes));
}

Create_field *
OPE_int::newCreateField(string anonname) {
    return createFieldHelper(cf, -1, MYSQL_TYPE_LONGLONG, anonname);
}

void
OPE_int::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = k;
    ope = OPE(key, plain_size * 8, ciph_size * 8);
}

void
OPE_int::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = "";
    ope = OPE("", plain_size*8, ciph_size*8);
}

Item *
OPE_int::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    ulong pval =  (ulong)static_cast<Item_int *>(ptext)->value;
    ulonglong enc = uint64FromZZ(ope.encrypt(to_ZZ(pval)));
    LOG(encl) << "OPE_int encrypt " << pval << " IV " << IV << "--->" << enc;
    unSetKey(k);
    return new Item_int(enc);
}

Item *
OPE_int::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    ulonglong cval = (ulonglong) static_cast<Item_int*>(ctext)->value;
    ulonglong dec = uint64FromZZ(ope.decrypt(ZZFromUint64(cval)));
    LOG(encl) << "OPE_int decrypt " << cval << " IV " << IV << "--->" << dec; 
    unSetKey(k);
    return new Item_int(dec);
}


OPE_str::OPE_str(Create_field * f, PRNG * prng)
    : EncLayer(f),
      key(prng->rand_string(key_bytes)),
      ope(key, plain_size*8, ciph_size*8)
{
    setKey(prng->rand_string(key_bytes));
}

Create_field *
OPE_str::newCreateField(string anonname) {
    return createFieldHelper(cf, -1, MYSQL_TYPE_LONGLONG, anonname, &my_charset_bin);
}

void
OPE_str::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = k;
    ope = OPE(key, plain_size * 8, ciph_size * 8);
}

void
OPE_str::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    key = "";
    ope = OPE("", plain_size*8, ciph_size*8);
}

Item *
OPE_str::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    string ps = ItemToString(ptext);
    if (ps.size() < plain_size)
        ps = ps + string(plain_size - ps.size(), 0);

    uint32_t pv = 0;

    for (uint i = 0; i < plain_size; i++) {
	pv = pv * 256 + (int)ps[i];
    }
    
    ZZ enc = ope.encrypt(to_ZZ(pv));
    unSetKey(k);
    return new Item_int((ulonglong) uint64FromZZ(enc));
}

Item *
OPE_str::decrypt(Item * ctext, uint64_t IV, const string &k) {
    thrower() << "cannot decrypt string from OPE";
}



/**************** HOM ***************************/

HOM::HOM(Create_field * f, PRNG * key)
    : EncLayer(f),
      sk(Paillier_priv::keygen(key, nbits))
{
}

Create_field *
HOM::newCreateField(string anonname) {
    return createFieldHelper(cf, 2*nbits/8, MYSQL_TYPE_VARCHAR, anonname, &my_charset_bin);
}

static ZZ
ItemIntToZZ(Item * ptext) {
    ulonglong val = static_cast<Item_int *>(ptext)->value;
    return ZZFromUint64(val);
}

static Item *
ZZToItemInt(const ZZ & val) {
    ulonglong v = uint64FromZZ(val);
    return new Item_int(v);
}

static Item *
ZZToItemStr(const ZZ & val) {
    string str = StringFromZZ(val);
    Item * newit = new Item_string(make_thd_string(str), str.length(), &my_charset_bin);
    newit->name = NULL; //no alias

    return newit;
}

static ZZ
ItemStrToZZ(Item* i) {
    string res = ItemToString(i);
    return ZZFromString(res);
}

void
HOM::setKey(const string &k) {
    if(k.empty()) {
        return;
    }
    //TODO: figure out how to make this work
    //PRNG *key = getLayerKey(get_AES_KEY(k), fullName(cf->onions[oAGG]->onionname, cf->tm->anonTableName), SECLEVEL::HOM);
    //sk = Paillier_priv::keygen(key, nbits);
    thrower() << "HOM setKey not implemented";
}

void
HOM::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    //TODO: set sk to 0
}

Item *
HOM::encrypt(Item * ptext, uint64_t IV, const string &k) {
    setKey(k);
    ZZ enc = sk.encrypt(ItemIntToZZ(ptext));
    unSetKey(k);
    return ZZToItemStr(enc);
}

Item *
HOM::decrypt(Item * ctext, uint64_t IV, const string &k) {
    setKey(k);
    ZZ enc = ItemStrToZZ(ctext);
    ZZ dec = sk.decrypt(enc);
    LOG(encl) << "HOM ciph " << enc << "---->" << dec; 
    unSetKey(k);
    return ZZToItemInt(dec);
}

static udf_func u_sum_a = {
    LEXSTRING("agg"),
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

static udf_func u_sum_f = {
    LEXSTRING("func_add_set"),
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
HOM::sumUDA(Item * expr, const string &k) {
    setKey(k);
    List<Item> l;
    l.push_back(expr);
    l.push_back(ZZToItemStr(sk.hompubkey()));
    unSetKey(k);
    return new Item_func_udf_str(&u_sum_a, l);
}

Item *
HOM::sumUDF(Item * i1, Item * i2, const string &k) {
    setKey(k);
    List<Item> l;
    l.push_back(i1);
    l.push_back(i2);
    l.push_back(ZZToItemStr(sk.hompubkey()));
    unSetKey(k);

    return new Item_func_udf_str(&u_sum_f, l);
}

/****PRODUCT*******/

static udf_func u_prod_a = {
    LEXSTRING("prod"),
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
ElGamal::prodUDA(Item * expr, const string &k) {
    setKey(k);
    List<Item> l;
    l.push_back(expr);
//    l.push_back(ZZToItemStr(sk.hompubkey()));
    unSetKey(k);
    return new Item_func_udf_str(&u_prod_a, l);
}

/******* SEARCH **************************/

Search::Search(Create_field * f, PRNG * key)
    : EncLayer(f)
{
    setKey(key->rand_string(key_bytes));
}

Create_field *
Search::newCreateField(string anonname) {
    return createFieldHelper(cf, -1, MYSQL_TYPE_BLOB, anonname, &my_charset_bin);
}


void
Search::setKey(const string &k) {
    if (k.empty()) {
        return;
    }
    rawkey = k;
    key = k;
    key.resize(key_bytes);
}

void
Search::unSetKey(const string &k) {
    if (k.empty()) {
        return;
    }
    rawkey = "";
    //TODO: zero key
}


//returns the concatenation of all words in the given list
static string
assembleWords(list<string> * words)
{
    string res = "";

    for (list<string>::iterator it = words->begin(); it != words->end();
         it++) {
        res = res + *it;
    }

    return res;
}

static string
encryptSWP(const string & key, const list<string> & words)
{
    auto l = SWP::encrypt(key, words);
    string r = assembleWords(l);
    delete l;
    return r;
}

static Token
token(const string & key, const string & word)
{
    return SWP::token(key, word);
}

//this function should in fact be provided by the programmer
//currently, we split by whitespaces
// only consider words at least 3 chars in len
// discard not unique objects
static list<string> *
tokenize(string text)
{

    list<string> tokens = split(text, " ,;:.");

    std::set<string> search_tokens;

    list<string> * res = new list<string>();

    for (list<string>::iterator it = tokens.begin(); it != tokens.end();
         it++) {
        if ((it->length() >= 3) &&
            (search_tokens.find(*it) == search_tokens.end())) {
            string token = toLowerCase(*it);
            search_tokens.insert(token);
            res->push_back(token);
        }
    }

    search_tokens.clear();
    return res;

}

static char *
newmem(const string & a) {
    unsigned int len = a.length();
    char * res = new char[len];
    memcpy(res, a.c_str(), len);
    return res;
}

Item *
Search::encrypt(Item * ptext, uint64_t IV, const std::string &k) {
    setKey(k);
    string plainstr = ItemToString(ptext);
    //TODO: remove string, string serves this purpose now..
    list<string> * tokens = tokenize(plainstr);
    string ciph = encryptSWP(key, *tokens);

    unSetKey(k);

    LOG(encl) << "SEARCH encrypt " << plainstr << " --> " << ciph;
  
    return new Item_string(newmem(ciph), ciph.length(), &my_charset_bin);	
}

Item *
Search::decrypt(Item * ctext, uint64_t IV, const std::string &k) {
    thrower() << "decryption from SWP not supported \n";
}

static udf_func u_search = {
    LEXSTRING("searchSWP"),
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


static string
searchstrip(string s) {
    cerr << "searchstrip input " << s << "\n";

    if (s[0] == '%') {
	s = s.substr(1, s.length() - 1);
    }
    uint len = s.length();
    if (s[len-1] == '%') {
	s = s.substr(0, len-1);
    }
    cerr << "searchstrip output " << s << "\n";
    return s;
}

Item *
Search::searchUDF(Item * field, Item * expr) {
    List<Item> l = List<Item>();

    l.push_back(field);

    // Add token
    
    Token t = token(key, string(searchstrip(ItemToString(expr))));
    Item_string * t1 =  new Item_string(newmem(t.ciph),
					t.ciph.length(), &my_charset_bin);
    t1->name = NULL; //no alias
    l.push_back(t1);
    
    Item_string * t2 = new Item_string(newmem(t.wordKey),
				       t.wordKey.length(), &my_charset_bin);
    t2->name = NULL;
    l.push_back(t2);
    
    return new Item_func_udf_int(&u_search, l);
}

/************ EncLayer factory creation  ********/

EncLayer *
EncLayerFactory::encLayer(onion o, SECLEVEL sl, Create_field * cf, PRNG * key) {
    switch (sl) {
    case SECLEVEL::ELG: {
       return new ElGamal(cf, key);
    } 
    case SECLEVEL::RND: {
	if (IsMySQLTypeNumeric(cf->sql_type) || (o == oOPE)) {
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
	if (IsMySQLTypeNumeric(cf->sql_type)) {
	    return new DETJOIN_int(cf, key);
	} else {
	    return new DETJOIN_str(cf, key);
	}
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

const std::vector<udf_func*> udf_list = {
    &u_decRNDInt,
    &u_decRNDString,
    &u_decDETInt,
    &u_decDETStr,
    &u_sum_f,
    &u_sum_a,
    &u_search
};
