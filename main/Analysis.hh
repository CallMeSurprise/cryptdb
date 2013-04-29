#pragma once

#include <util/onions.hh>
#include <parser/embedmysql.hh>
#include <parser/stringify.hh>
#include <main/MultiPrinc.hh>
#include <util/cryptdb_log.hh>

using namespace std;


/**
 * Used to keep track of encryption constraints during
 * analysis
 */
class EncSet {
public:
    EncSet(OnionLevelFieldMap input) : osl(input) {}
    EncSet(); // TODO(stephentu): move ctor here
    EncSet(FieldMeta * fm);
    EncSet(const OLK & olk);
    
    /**
     * decides which encryption scheme to use out of multiple in a set
     */
    OLK chooseOne() const;

    bool contains(const OLK & olk) const;
    
    EncSet intersect(const EncSet & es2) const;

    bool empty() const { return osl.empty(); }

    bool singleton() const { return osl.size() == 1; }

    EncDesc encdesc();
    
    OLK extract_singleton() const {
        assert_s(singleton(), string("encset has size ") + StringFromVal(osl.size()));
	auto it = osl.begin();
	return OLK(it->first, it->second.first, it->second.second);
    }

    void setFieldForOnion(onion o, FieldMeta * fm);
    
    OnionLevelFieldMap osl; //max level on each onion
};


ostream&
operator<<(ostream &out, const EncSet & es);

const EncSet EQ_EncSet = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oDET,   LevelFieldPair(SECLEVEL::DET, NULL)},
            {oOPE,   LevelFieldPair(SECLEVEL::OPE, NULL)},
        }
};

const EncSet JOIN_EncSet = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oDET,   LevelFieldPair(SECLEVEL::DETJOIN, NULL)},
        }
};

const EncSet ORD_EncSet = {
    {
	{oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
	{oOPE, LevelFieldPair(SECLEVEL::OPE, NULL)},
    }
};

const EncSet PLAIN_EncSet = {
    {
	{oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
    }
};

//todo: there should be a map of FULL_EncSets depending on item type
const EncSet FULL_EncSet = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oDET, LevelFieldPair(SECLEVEL::RND, NULL)},
            {oOPE, LevelFieldPair(SECLEVEL::RND, NULL)},
            {oAGG, LevelFieldPair(SECLEVEL::HOM, NULL)},
            {oSWP, LevelFieldPair(SECLEVEL::SEARCH, NULL)},
            {oELG, LevelFieldPair(SECLEVEL::ELG, NULL)},
        }
};

const EncSet FULL_EncSet_Str = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oDET, LevelFieldPair(SECLEVEL::RND, NULL)},
            {oOPE, LevelFieldPair(SECLEVEL::RND, NULL)},
            {oSWP, LevelFieldPair(SECLEVEL::SEARCH, NULL)},
        }
};

const EncSet FULL_EncSet_Int = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oDET, LevelFieldPair(SECLEVEL::RND, NULL)},
            {oOPE, LevelFieldPair(SECLEVEL::RND, NULL)},
            {oAGG, LevelFieldPair(SECLEVEL::HOM, NULL)},
            {oELG, LevelFieldPair(SECLEVEL::ELG, NULL)},
        }
};

const EncSet Search_EncSet = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oSWP, LevelFieldPair(SECLEVEL::SEARCH, NULL)},
        }
};

const EncSet ADD_EncSet = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oAGG, LevelFieldPair(SECLEVEL::HOM, NULL)},
        }
};

// not sure if needed 
const EncSet PROD_EncSet = {
        {
	    {oPLAIN, LevelFieldPair(SECLEVEL::PLAINVAL, NULL)},
            {oELG, LevelFieldPair(SECLEVEL::ELG, NULL)},
        }
};

const EncSet EMPTY_EncSet = {
        {{}}
};


// returns true if any of the layers in ed
// need salt
bool
needsSalt(EncSet ed);

/***************************************************/

extern "C" void *create_embedded_thd(int client_flag);

typedef struct ReturnField {
    bool is_salt;
    std::string field_called;
    OLK olk; // if !olk.key, field is not encrypted
    int pos_salt; //position of salt of this field in the query results,
                  // or -1 if such salt was not requested
    string stringify();
} ReturnField;

typedef struct ReturnMeta {
    map<int, ReturnField> rfmeta;
    string stringify();
    TMKM tmkm;
} ReturnMeta;


class OnionAdjustExcept {
public:
    OnionAdjustExcept(onion o, FieldMeta * fm, SECLEVEL l, Item_field * itf) :
	o(o), fm(fm), tolevel(l), itf(itf) {}

    onion o;
    FieldMeta * fm;
    SECLEVEL tolevel;
    Item_field * itf;
};


class reason {
public:
    reason(const EncSet & es, const std::string &why_t_arg,
                Item *why_t_item_arg)
	:  encset(es), why_t(why_t_arg), why_t_item(why_t_item_arg)
	{ childr = new std::list<reason>();}
    reason(): encset(EMPTY_EncSet), why_t(""), why_t_item(NULL), childr(NULL) {}
    void add_child(const reason & ch) {
	childr->push_back(ch);
    }
    
    EncSet encset;    

    std::string why_t;
    Item *why_t_item;
    
    std::list<reason> * childr;
};

ostream&
operator<<(ostream &out, const reason &r);

// The rewrite plan of a lex node: the information a
// node remembers after gather, to be used during rewrite
// Other more specific RewritePlan-s inherit from this class
class RewritePlan {
public:
    reason r;
    EncSet es_out; // encset that this item can output

    RewritePlan(const EncSet & es, reason r) : r(r), es_out(es) {};
    RewritePlan() {};
    
    //only keep plans that have parent_olk in es
//    void restrict(const EncSet & es);

};


//rewrite plan in which we only need to remember one olk
// to know how to rewrite
class RewritePlanOneOLK: public RewritePlan {
public:
    OLK olk;
    // the following store how to rewrite children
    RewritePlan ** childr_rp;
    
    RewritePlanOneOLK(const EncSet & es_out,
		      const OLK & olk,
		      RewritePlan ** childr_rp,
		      reason r) : RewritePlan(es_out, r),
				  olk(olk),
				  childr_rp(childr_rp) {}
};

typedef class ConnectionInfo {
public:
    std::string server;
    uint port;
    std::string user;
    std::string passwd;
   
    ConnectionInfo(std::string s, std::string u, std::string p, uint port = 0) :
	server(s), port(port), user(u), passwd(p) {};
    ConnectionInfo() : server(""), port(0), user(""), passwd("") {};
    
} ConnectionInfo;

ostream&
operator<<(ostream &out, const RewritePlan * rp);


// state maintained at the proxy
typedef struct ProxyState {

    ProxyState(): conn(NULL), e_conn(NULL), encByDefault(true),
		  masterKey(NULL), schema(NULL), totalTables(0), mp(NULL) {}
    ConnectionInfo ci;

    // connection to remote and embedded server
    Connect*       conn;
    Connect*       e_conn;

    bool           encByDefault;
    AES_KEY*       masterKey;
    
    SchemaInfo*    schema;
    unsigned int   totalTables;

    MultiPrinc*    mp;

    ~ProxyState();
} ProxyState;


class Analysis {
public:
    Analysis(ProxyState * ps) : ps(ps), pos(0), rmeta(new ReturnMeta()) {}
    
    Analysis(): ps(NULL), pos(0), rmeta(new ReturnMeta()) {}
 
    // pointer to proxy metadata 
    ProxyState * ps;

    /* Temporary structures for processing one query */
   
    unsigned int pos; //a counter indicating how many projection fields have been analyzed so far                                                                    
    std::map<FieldMeta *, salt_type>    salts;
    TMKM                                tmkm; //for multi princ
    std::map<Item *, RewritePlan *>     rewritePlans;

    // information for decrypting results 
    ReturnMeta * rmeta;

private:
    MYSQL * m;

};

typedef struct ConnectionData {
    std::string server;
    std::string user;
    std::string psswd;
    std::string dbname;
    uint port;

    ConnectionData() {}

    ConnectionData(std::string serverarg, std::string userarg, std::string psswdarg, std::string dbnamearg, uint portarg = 0) {
        server = serverarg;
        user = userarg;
        psswd = psswdarg;
        dbname = dbnamearg;
        port = portarg;
    }

} ConnectionData;

