#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <set>
#include <list>
#include <algorithm>
#include <stdio.h>
#include <typeinfo>

#include <main/cdb_rewrite.hh>
#include <util/cryptdb_log.hh>
#include <main/CryptoHandlers.hh>
#include <parser/lex_util.hh>


#include "field.h"

#include <main/MultiPrinc.hh>

using namespace std;

//TODO: replace table/field with FieldMeta * for speed and conciseness

#define UNIMPLEMENTED \
        throw runtime_error(string("Unimplemented: ") + \
                        string(__PRETTY_FUNCTION__))

//TODO: rewrite_proj may not need to be part of each class;
// it just does gather, choos and then rewrite

static Item *
stringToItemField(string field, string table, Item_field * itf) {

    THD * thd = current_thd;
    assert(thd);
    Item_field * res = new Item_field(thd, itf);
    res->name = NULL; //no alias
    res->field_name = make_thd_string(field);
    res->table_name = make_thd_string(table);

    return res;
}

static inline string
extract_fieldname(Item_field *i)
{
    stringstream fieldtemp;
    fieldtemp << *i;
    return fieldtemp.str();
}


//TODO: remove this at some point
static inline void
mysql_query_wrapper(MYSQL *m, const string &q)
{
    if (mysql_query(m, q.c_str())) {
        cryptdb_err() << "query failed: " << q
                << " reason: " << mysql_error(m);
    }

    // HACK(stephentu):
    // Calling mysql_query seems to have destructive effects
    // on the current_thd. Thus, we must call create_embedded_thd
    // again.
    void* ret = create_embedded_thd(0);
    if (!ret) assert(false);
}

static void
createMetaTablesIfNotExists(ProxyState & ps)
{
    assert(ps.e_conn->execute("CREATE DATABASE IF NOT EXISTS proxy_db"));

    assert(ps.e_conn->execute(
                   "CREATE TABLE IF NOT EXISTS proxy_db.table_info"
                   "( id bigint NOT NULL PRIMARY KEY"
                   ", dbname varchar(64) NOT NULL"
                   ", name varchar(64) NOT NULL"
                   ", anon_name varchar(64) NOT NULL"
                   ", UNIQUE INDEX idx_table_name( dbname, name )"
                   ") ENGINE=InnoDB;"));

    assert(ps.e_conn->execute(
                   "CREATE TABLE IF NOT EXISTS proxy_db.column_info"
                   "( id bigint NOT NULL auto_increment PRIMARY KEY"
                   ", table_id bigint NOT NULL"
                   ", name varchar(64) NOT NULL"
                   ", anon_det_name varchar(64)"
                   ", anon_ope_name varchar(64)"
                   ", anon_agg_name varchar(64)"
                   ", anon_swp_name varchar(64)"
                   ", salt_name varchar(4096)"
                   ", is_encrypted tinyint NOT NULL"
                   ", can_be_null tinyint NOT NULL"
                   ", has_ope tinyint NOT NULL"
                   ", has_agg tinyint NOT NULL"
                   ", has_search tinyint NOT NULL"
                   ", has_salt tinyint NOT NULL"
                   ", ope_used tinyint NOT NULL"
                   ", agg_used tinyint NOT NULL"
                   ", search_used tinyint NOT NULL"
                   ", sec_level_ope enum"
                   "      ( 'INVALID'"
                   "      , 'PLAIN'"
                   "      , 'PLAIN_DET'"
                   "      , 'DETJOIN'"
                   "      , 'DET'"
                   "      , 'DET'"
                   "      , 'PLAIN_OPE'"
                   "      , 'OPEJOIN'"
                   "      , 'OPE'"
                   "      , 'OPE'"
                   "      , 'PLAIN_AGG'"
                   "      , 'SEMANTIC_AGG'"
                   "      , 'PLAIN_SWP'"
                   "      , 'SWP'"
                   "      , 'SEMANTIC_VAL'"
                   "      , 'SECLEVEL_LAST'"
                   "      ) NOT NULL DEFAULT 'INVALID'"
                   ", sec_level_det enum"
                   "      ( 'INVALID'"
                   "      , 'PLAIN'"
                   "      , 'PLAIN_DET'"
                   "      , 'DETJOIN'"
                   "      , 'DET'"
                   "      , 'DET'"
                   "      , 'PLAIN_OPE'"
                   "      , 'OPEJOIN'"
                   "      , 'OPE'"
                   "      , 'OPE'"
                   "      , 'PLAIN_AGG'"
                   "      , 'SEMANTIC_AGG'"
                   "      , 'PLAIN_SWP'"
                   "      , 'SWP'"
                   "      , 'SEMANTIC_VAL'"
                   "      , 'SECLEVEL_LAST'"
                   "      ) NOT NULL DEFAULT 'INVALID'"
                   ", INDEX idx_column_name( name )"
                   ", FOREIGN KEY( table_id ) REFERENCES table_info( id ) ON DELETE CASCADE"
                   ") ENGINE=InnoDB;"));
}


static void
printEC(Connect * e_conn, const string & command) {
    DBResult * dbres;
    assert_s(e_conn->execute(command, dbres), "command failed");
    ResType res = dbres->unpack();
    printRes(res);
}

static void
printEmbeddedState(ProxyState & ps) {
    printEC(ps.e_conn, "use proxy_db;");
    printEC(ps.e_conn, "show databases;");
    printEC(ps.e_conn, "show tables;");
    printEC(ps.e_conn, "select * from column_info;");
    printEC(ps.e_conn, "select * from table_info;");
}


static void
initSchema(ProxyState & ps)
{

//    printEmbeddedState(ps);

    cerr << "warning: initSchema does not init enc layers correctly from shadow db\n";
    createMetaTablesIfNotExists(ps);

    vector<string> tablelist;

    DBResult * dbres;
    assert(ps.e_conn->execute("SELECT id, dbname, name, anon_name FROM proxy_db.table_info", dbres));
    ScopedMySQLRes r(dbres->n);
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(r.res()))) {
        unsigned long *l = mysql_fetch_lengths(r.res());
        assert(l != NULL);
        TableMeta *tm = new TableMeta;
        tm->tableNo = (unsigned int) atoi(string(row[0], l[0]).c_str());
        tm->anonTableName = string(row[3], l[3]);
        tm->has_salt = false;
        string dbname(row[1], l[1]);
        string origTableName(row[2], l[2]);
        // tableMetaMap keys should include dbname: make_pair(dbname, origTableName)?
        ps.schema->tableMetaMap[origTableName] = tm;
        ps.schema->totalTables++;

        string create_table_query;
        {
            string q = "SHOW CREATE TABLE `" + dbname + "`.`" + origTableName + "`";
            DBResult * dbres = NULL;
            assert(ps.e_conn->execute(q, dbres));
            ScopedMySQLRes r(dbres->n);
            assert(mysql_num_rows(r.res()) == 1);
            assert(mysql_num_fields(r.res()) == 2);
            MYSQL_ROW row = mysql_fetch_row(r.res());
            unsigned long *lengths = mysql_fetch_lengths(r.res());
            create_table_query = string(row[1], lengths[1]);
        }

        query_parse parser(dbname, create_table_query);
        LEX *lex = parser.lex();
        assert(lex->sql_command == SQLCOM_CREATE_TABLE);

        // fetch all the column info for this table
        {
            string q = "SELECT "
                       "c.name, "

                       "c.has_ope, "
                       "c.has_agg, "
                       "c.has_search, "

                       "c.anon_det_name, "
                       "c.anon_ope_name, "
                       "c.anon_agg_name, "
                       "c.anon_swp_name, "

                       "c.sec_level_det, "
                       "c.sec_level_ope, "

                       "c.salt_name, "
                       "c.is_encrypted, "
                       "c.can_be_null, "

                       "c.has_salt "

                       //TODO: what do these fields do?
                       //"c.ope_used, "
                       //"c.agg_used, "
                       //"c.search_used, "

                       "FROM proxy_db.column_info c, proxy_db.table_info t "
                       "WHERE t.name = '" + origTableName + "'"
                            " AND t.dbname = '" + dbname + "'"
                            " AND c.table_id = t.id";

            DBResult * dbres;
            assert(ps.e_conn->execute(q, dbres));

            ScopedMySQLRes r(dbres->n);
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(r.res()))) {
                unsigned long *l = mysql_fetch_lengths(r.res());
                assert(l != NULL);

                FieldMeta *fm = new FieldMeta;
                fm->tm = tm;

                size_t i = 0, j = 0;
                fm->fname = string(row[i++], l[j++]);

                bool has_ope = string(row[i++], l[j++]) == "1";
                bool has_agg = string(row[i++], l[j++]) == "1";
                bool has_swp = string(row[i++], l[j++]) == "1";

                if (fm->onions.size() > 0) {
                    fm->onions[oDET]->onionname = string(row[i++], l[j++]);

                    if (has_ope) { fm->onions[oOPE]->onionname = string(row[i++], l[j++]); }
                    else         { i++; j++; }

                    if (has_agg) { fm->onions[oAGG]->onionname = string(row[i++], l[j++]); }
                    else         { i++; j++; }

                    if (has_swp) { fm->onions[oSWP]->onionname = string(row[i++], l[j++]); }
                    else         { i++; j++; }

                    OnionLevelMap om;

                    om[oDET] = string_to_sec_level(string(row[i++], l[j++]));

                    if (has_ope) { om[oOPE] = string_to_sec_level(string(row[i++], l[j++])); }
                    else         { i++; j++; }

                    if (has_agg) { om[oAGG] = SECLEVEL::HOM; }

                    if (has_swp) { om[oSWP] = SECLEVEL::SEARCH; }

                    fm->encdesc = EncDesc(om);

                    fm->salt_name = string(row[i++], l[j++]);
                }

                i++; j++; // is_encrypted
                i++; j++; // can_be_null

                fm->has_salt = string(row[i++], l[j++]) == "1";

                tm->fieldNames.push_back(fm->fname);
                tm->fieldMetaMap[fm->fname] = fm;
            }
        }
    }
    printEmbeddedState(ps);
}

//l gets updated to the new level
static void
removeOnionLayer(FieldMeta * fm, Item_field * itf, Analysis & a, onion o, SECLEVEL & l, const string & cur_db) {

    OnionMeta * om    = getAssert(fm->onions, o);
    string fieldanon  = om->onionname;
    string tableanon  = fm->tm->anonTableName;

    //removes onion layer at the DB
    stringstream query;
    query << "UPDATE " << tableanon << " SET " << fieldanon  << " = ";

    Item * decUDF = om->layers.back()->decryptUDF(stringToItemField(fieldanon,     tableanon, itf),
		  				  stringToItemField(fm->salt_name, tableanon, itf));

    query << *decUDF << ";";

    cerr << "\nADJUST: \n" << query.str() << "\n";

    string usedb = "USE " +  cur_db + ";";
    //HACk: make sure right cur_db in other ways
    assert_s(a.ps->conn->execute(usedb),  "failed to execute " + usedb);
    //execute decryption query
    assert_s(a.ps->conn->execute(query.str()), "failed to execute onion decryption query");

    LOG(cdb_v) << "adjust onions: \n" << query.str() << "\n";

    //remove onion layer in schema
    om->layers.pop_back();
    l = om->layers.back()->level();
    fm->encdesc.olm[o] = l;

    //todo:we do not need olm any more; then, do we need level in Enclayer?
}

/*
 * Adjusts the onion for a field fm/itf to level: tolevel.
 *
 * Issues queries for decryption to the DBMS.
 *
 * Adjusts the schema metadata at the proxy about onion layers. Propagates the
 * changed schema to persistent storage.
 *
 */
static void
adjustOnion(onion o, FieldMeta * fm, SECLEVEL tolevel, Item_field *itf, Analysis & a, const string & cur_db) {

    //TODO: use getAssert in more places
    SECLEVEL newlevel = getAssert(fm->encdesc.olm, o);

    while (newlevel > tolevel) {
	removeOnionLayer(fm, itf, a, o, newlevel, cur_db);
    }
    assert(newlevel == tolevel);
}
//TODO: propagate these adjustments in the embedded database?

static inline bool
FieldQualifies(const FieldMeta * restriction,
               const FieldMeta * field)
{
    return !restriction || restriction == field;
}


static void
addToReturn(ReturnMeta * rm, int pos, const OLK & constr,  bool has_salt) {
    ReturnField rf = ReturnField();
    rf.is_salt = false;
    rf.olk = constr;
    if (has_salt) {
        rf.pos_salt = pos+1;
    } else {
        rf.pos_salt = -1;
    }
    rm->rfmeta[pos] = rf;
}

static void
addToReturn(ReturnMeta * rm, int pos, const OLK & constr, bool has_salt, string name) {
    addToReturn(rm, pos, constr, has_salt);
    rm->rfmeta[pos].field_called = name;
}

static void
addSaltToReturn(ReturnMeta * rm, int pos) {
    ReturnField rf = ReturnField();
    rf.is_salt = true;
    rf.olk = OLK();
    rf.pos_salt = -1;
    rm->rfmeta[pos] = rf;
}

//TODO: which encrypt/decrypt should handle null?
static Item *
encrypt_item_layers(Item * i, onion o, list<EncLayer *> & layers, Analysis &a, FieldMeta *fm = 0, uint64_t IV = 0) {
    if (o == oPLAIN) {//Unencrypted item
		return i;
    }

    // Encrypted item

    assert_s(layers.size() > 0, "field must have at least one layer");
    Item * enc = i;
    Item * prev_enc = NULL;
    for (auto layer : layers) {
        LOG(encl) << "encrypt layer " << levelnames[(int)layer->level()] << "\n";
        string key = "";
        if (a.ps->mp) {
            key = a.ps->mp->get_key(fullName(fm->fname, fm->tm->anonTableName), a.tmkm);
            cerr << "mp key " << key << endl;
        }
        enc = layer->encrypt(enc, IV, key);
        //need to free space for all enc
        //except the last one
        if (prev_enc) {
            delete prev_enc;
        }
        prev_enc = enc;
    }

    return enc;
}

static Item *
decrypt_item_layers(Item * i, onion o,  list<EncLayer *> & layers, uint64_t IV, Analysis &a, FieldMeta *fm, const vector<Item *> &res) {

    if (o == oPLAIN) {// Unencrypted item
	return i;
    }

    // Encrypted item

    Item * dec = i;
    Item * prev_dec = NULL;

    for (auto it = layers.rbegin(); it != layers.rend(); ++it) {
        string key = "";
        if (a.ps->mp) {
            if (a.tmkm.processingQuery) {
                key = a.ps->mp->get_key(fullName(fm->fname, fm->tm->anonTableName), a.tmkm);
            } else {
                key = a.ps->mp->get_key(fullName(fm->fname, fm->tm->anonTableName), a.tmkm, res);
            }
            cerr << "mp decrypt key " << key << endl;
        }
        dec = (*it)->decrypt(dec, IV, key);
        LOG(cdb_v) << "dec okay";
        //need to free space for all decs except last
        if (prev_dec) {
            delete prev_dec;
        }
        prev_dec = dec;
    }

    return dec;
}

// encrypts a constant item based on the information in a
static Item *
encrypt_item(Item * i, const OLK & olk, Analysis & a)
{
    if (olk.l == SECLEVEL::PLAINVAL)
        return i;

    FieldMeta * fm = olk.key;
    assert(fm);

    onion o        = olk.o;
    LOG(cdb_v) << fm->fname << " " << fm->onions.size();

    auto it = a.salts.find(fm);
    salt_type IV = 0;
    if (it != a.salts.end()) {
	IV = it->second;
    }
    return encrypt_item_layers(i, o, fm->onions[o]->layers, a, fm, IV);
}

static void
encrypt_item_all_onions(Item * i, FieldMeta * fm,
                        uint64_t IV, vector<Item*> & l, Analysis &a) {

    for (auto it : fm->onions) {
        l.push_back(encrypt_item_layers(i, it.first, it.second->layers, a, fm, IV));
    }
}

static Item *
decrypt_item(FieldMeta * fm, onion o, Item * i, uint64_t IV, Analysis &a, vector<Item *> &res) {
    return decrypt_item_layers(i, o, fm->onions[o]->layers, IV, a, fm, res);
}


// anonymizes table name based on the information in a.schema
static string
anonymize_table_name(const string &tname,
                     Analysis & a)
{
    return getAssert(a.ps->schema->tableMetaMap, tname)->anonTableName;
}

class CItemType {
 public:
    virtual RewritePlan * do_gather(Item *, reason&, Analysis &) const = 0;
    virtual Item * do_optimize(Item *, Analysis &) const = 0;
    virtual Item * do_rewrite(Item *,
			      const OLK & constr, const RewritePlan * rp,
			      Analysis &) const = 0;
    virtual void   do_rewrite_insert(Item *, Analysis &, vector<Item *> &, FieldMeta *fm) const = 0;
};


/*
 * Directories for locating an appropriate CItemType for a given Item.
 */
template <class T>
class CItemTypeDir : public CItemType {
 public:
    void reg(T t, CItemType *ct) {
        auto x = types.find(t);
        if (x != types.end())
            thrower() << "duplicate key " << t;
        types[t] = ct;
    }

    RewritePlan * do_gather(Item *i, reason &tr, Analysis &a) const {
        return lookup(i)->do_gather(i, tr, a);
    }

    Item* do_optimize(Item *i, Analysis &a) const {
        return lookup(i)->do_optimize(i, a);
    }

    Item* do_rewrite(Item *i,
		     const OLK & constr, const RewritePlan * rp,
		     Analysis &a) const {
        return lookup(i)->do_rewrite(i, constr, rp, a);
    }

    void do_rewrite_insert(Item *i, Analysis &a, vector<Item *> &l, FieldMeta *fm) const {
        lookup(i)->do_rewrite_insert(i, a, l, fm);
    }


 protected:
    virtual CItemType *lookup(Item *i) const = 0;

    CItemType *do_lookup(Item *i, T t, const char *errname) const {
        auto x = types.find(t);
        if (x == types.end())
            thrower() << "missing " << errname << " " << t << " in " << *i;
        return x->second;
    }

 private:
    std::map<T, CItemType*> types;
};

static class ANON : public CItemTypeDir<Item::Type> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, i->type(), "type");
    }
} itemTypes;

static class CItemFuncDir : public CItemTypeDir<Item_func::Functype> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, ((Item_func *) i)->functype(), "func type");
    }
 public:
    CItemFuncDir() {
        itemTypes.reg(Item::Type::FUNC_ITEM, this);
        itemTypes.reg(Item::Type::COND_ITEM, this);
    }
} funcTypes;

static class CItemSumFuncDir : public CItemTypeDir<Item_sum::Sumfunctype> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, ((Item_sum *) i)->sum_func(), "sumfunc type");
    }
 public:
    CItemSumFuncDir() {
        itemTypes.reg(Item::Type::SUM_FUNC_ITEM, this);
    }
} sumFuncTypes;

static class CItemFuncNameDir : public CItemTypeDir<std::string> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, ((Item_func *) i)->func_name(), "func name");
    }
 public:
    CItemFuncNameDir() {
        funcTypes.reg(Item_func::Functype::UNKNOWN_FUNC, this);
        funcTypes.reg(Item_func::Functype::NOW_FUNC, this);
    }
} funcNames;


/*
 * Helper functions to look up via directory & invoke method.
 */
static inline RewritePlan *
gather(Item *i, reason &tr, Analysis & a)
{
    return itemTypes.do_gather(i, tr, a);
}

// An implementation of gather for the common case
// Works for Item_func with two arguments, solution encset is intersect of
// children and my_es
// Only works with nodes with one outgoing encset, which could be other_encset
// if encset_from_intersection is false, or else is the intersection with the children
static RewritePlan *
typical_gather(Analysis & a, Item_func * i,
	     const EncSet & my_es, string why, reason & my_r,
	     bool encset_from_intersection, const EncSet & other_encset = PLAIN_EncSet)
{

    Item **args = i->arguments();
    assert(i->argument_count() == 2);

    reason r1, r2;
    RewritePlan ** childr_rp = (RewritePlan**)malloc(sizeof(RewritePlan *));
    childr_rp[1] = gather(args[0], r1, a);
    childr_rp[2] = gather(args[1], r2, a);

    EncSet solution = my_es.intersect(childr_rp[1]->es_out).
	                    intersect(childr_rp[2]->es_out);

    if (solution.empty()) {
	    cerr << "crypto schemes does not support this query BECAUSE " << i << "NEEDS " << my_es << "\n" \
	        << " BECAUSE " << why << "\n" \
	        << " AND children have:  " << r1 << r2 << "\n";
	    assert(false);
    }

    EncSet out_es;
    if (encset_from_intersection) {
	    assert_s(solution.singleton(), "cannot use basic_gather with more outgoing encsets");
	    out_es = solution;
    } else {
	    out_es = PLAIN_EncSet;
    }

    my_r = reason(out_es, why, i);
    my_r.add_child(r1);
    my_r.add_child(r2);

    return new RewritePlanOneOLK(out_es.extract_singleton(),
				 solution.chooseOne(), childr_rp,
				 my_r);
}



// TODO:
// should be able to support general updates such as
// UPDATE table SET x = 2, y = y + 1, z = y+2, z =z +1, w = y, l = x
// this has a few corner cases, since y can only use HOM
// onion so does w, but not l

//analyzes an expression of the form field = val expression from
// an UPDATE
static inline void
analyze_update(Item_field * field, Item * val, Analysis & a) {

    reason r;
    RewritePlan * rp = gather(val, r, a);
    a.rewritePlans[val] = rp;
    a.rewritePlans[field] = gather(field, r, a);

    //TODO: an optimization could be performed here to support more updates
    // For example: SET x = x+1, x = 2 --> no need to invalidate DET and OPE
    // onions because first SET does not matter
}

//TODO: need to check somewhere that plain is returned
static inline void
analyze(Item *i, Analysis & a)
{
    assert(i != NULL);
    LOG(cdb_v) << "calling gather for item " << *i;
    reason r;
    a.rewritePlans[i] = gather(i, r, a);
}

static inline void
optimize(Item **i, Analysis &a) {
    //TODO
/*Item *i0 = itemTypes.do_optimize(*i, a);
    if (i0 != *i) {
        // item i was optimized (replaced) by i0
        if (a.itemRewritePlans.find(*i) != a.itemRewritePlans.end()) {
            a.itemRewritePlans[i0] = a.itemRewritePlans[*i];
            a.itemRewritePlans.erase(*i);
        }
        *i = i0;
    } */
}

// this function should be called at the root of a tree of items
// that should be rewritten
static inline Item *
rewrite(Item *i, const OLK & constr, Analysis &a, string context = "")
{
    if (context.size()) {
		context = " for " + context;
    }
    RewritePlan * rp = getAssert(a.rewritePlans, i);
    assert(rp);
    if (!rp->es_out.contains(constr)) {
		cerr << "query cannot be supported because " << i << " needs to return " << constr << context << "\n" \
			 << "BUT it can only return " << rp->es_out << " BECAUSE " << rp->r << "\n";
		assert(false);
    }
    return itemTypes.do_rewrite(i, constr, rp, a);
}

template <class T>
static Item *
do_optimize_const_item(T *i, Analysis &a) {

    return i;

    /* TODO for later
    if (i->const_item()) {
        // ask embedded DB to eval this const item,
        // then replace this item with the eval-ed constant
        //
        // WARNING: we must make sure that the primitives like
        // int literals, string literals, override this method
        // and not ask the server.

        // very hacky...
        stringstream buf;
        buf << "SELECT " << *i;
        string q(buf.str());
        LOG(cdb_v) << q;

	DBResult * dbres = NULL;
	assert(a.ps->e_conn->execute(q, dbres));

        THD *thd = current_thd;
        assert(thd != NULL);

        MYSQL_RES *r = dbres->n;
        if (r) {
            Item *rep = NULL;

            assert(mysql_num_rows(r) == 1);
            assert(mysql_num_fields(r) == 1);

            MYSQL_FIELD *field = mysql_fetch_field_direct(r, 0);
            assert(field != NULL);

            MYSQL_ROW row = mysql_fetch_row(r);
            assert(row != NULL);

            char *p = row[0];
            unsigned long *lengths = mysql_fetch_lengths(r);
            assert(lengths != NULL);
            if (p) {

                LOG(cdb_v) << "p: " << p;
                LOG(cdb_v) << "field->type: " << field->type;

                switch (field->type) {
                    case MYSQL_TYPE_SHORT:
                    case MYSQL_TYPE_LONG:
                    case MYSQL_TYPE_LONGLONG:
                    case MYSQL_TYPE_INT24:
                        rep = new Item_int((long long) strtoll(p, NULL, 10));
                        break;
                    case MYSQL_TYPE_FLOAT:
                    case MYSQL_TYPE_DOUBLE:
                        rep = new Item_float(p, lengths[0]);
                        break;
                    case MYSQL_TYPE_DECIMAL:
                    case MYSQL_TYPE_NEWDECIMAL:
                        rep = new Item_decimal(p, lengths[0], i->default_charset());
                        break;
                    case MYSQL_TYPE_VARCHAR:
                    case MYSQL_TYPE_VAR_STRING:
                        rep = new Item_string(thd->strdup(p),
                                              lengths[0],
                                              i->default_charset());
                        break;
                    default:
                        // TODO(stephentu): implement the rest of the data types
                        break;
                }
            } else {
                // this represents NULL
                rep = new Item_null();
            }
            mysql_free_result(r);
            if (rep != NULL) {
                rep->name = i->name;
                return rep;
            }
        } else {
            // some error in dealing with the DB
            LOG(warn) << "could not retrieve result set";
        }
    }
    return i;

    */
}

template <class T>
static Item *
do_optimize_type_self_and_args(T *i, Analysis &a) {
    UNIMPLEMENTED;
    /*
    Item *i0 = do_optimize_const_item(i, a);
    if (i0 == i) {
        // no optimizations done at top level
        // try children
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            optimize(&args[x], a);
        }
        return i;
    } else {
        return i0;
	}*/
}

// in place rewriting of arguments
template <class T>
static void
rewrite_args_FN(T * i, const OLK & constr,
		const RewritePlanOneOLK * rp, Analysis &a) {

    Item **args = i->arguments();
    uint count = i->argument_count();
    for (uint x = 0; x < count; x++) {
        args[x] = itemTypes.do_rewrite(args[x],
				       rp->olk, rp->childr_rp[x],
				       a);
        args[x]->name = NULL; // args should never have aliases...
    }
}

// rewrites the arguments of aggregators
// no_args specifies a certain number of arguments that I must have
// if negative, i can have any no. of arguments
static list<Item *>
rewrite_agg_args(Item_sum * oldi, const OLK & constr, const RewritePlanOneOLK * rp,
		 Analysis & a, int no_args = -1) {
    if (no_args >= 0) {
	assert_s(oldi->get_arg_count() == (uint)no_args,
		 "support for aggregation with this number of arguments not currently implemented");
    } else {
	no_args = oldi->get_arg_count();
    }

    list<Item *> res = list<Item *>();
    for (int j = 0; j < no_args; j++) {
	Item * child_item = oldi->get_arg(j);
	child_item = itemTypes.do_rewrite(child_item, rp->olk, rp->childr_rp[j], a);
	res.push_back(child_item);
    }

    return res;
}


/*
 * CItemType classes for supported Items: supporting machinery.
 */
template<class T>
class CItemSubtype : public CItemType {
    virtual RewritePlan * do_gather(Item *i, reason &tr, Analysis & a) const {
        return do_gather_type((T*) i, tr, a);
    }
    virtual Item* do_optimize(Item *i, Analysis & a) const {
        return do_optimize_type((T*) i, a);
    }
    virtual Item* do_rewrite(Item *i,
			     const OLK & constr, const RewritePlan * rp,
			     Analysis & a) const {
        return do_rewrite_type((T*) i, constr, rp, a);
    }
    virtual void  do_rewrite_insert(Item *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const {
        do_rewrite_insert_type((T*) i, a, l, fm);
    }
 private:
    virtual RewritePlan * do_gather_type(T *, reason&, Analysis & a) const = 0;
    virtual Item * do_optimize_type(T *i, Analysis & a) const {
        return do_optimize_const_item(i, a);
    }
    virtual Item * do_rewrite_type(T *i,
				   const OLK & constr, const RewritePlan * rp,
				   Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type L676 " << *i;
	assert_s(false, "why is this rewrite called?");
        return i;
    }
    virtual void   do_rewrite_insert_type(T *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const {
        // default is un-implemented. we'll implement these as they come
        UNIMPLEMENTED;
    }
};

template<class T, Item::Type TYPE>
class CItemSubtypeIT : public CItemSubtype<T> {
 public:
    CItemSubtypeIT() { itemTypes.reg(TYPE, this); }
};

template<class T, Item_func::Functype TYPE>
class CItemSubtypeFT : public CItemSubtype<T> {
 public:
    CItemSubtypeFT() { funcTypes.reg(TYPE, this); }
};

template<class T, Item_sum::Sumfunctype TYPE>
class CItemSubtypeST : public CItemSubtype<T> {
 public:
    CItemSubtypeST() { sumFuncTypes.reg(TYPE, this); }
};

template<class T, const char *TYPE>
class CItemSubtypeFN : public CItemSubtype<T> {
 public:
    CItemSubtypeFN() { funcNames.reg(std::string(TYPE), this); }
};

// returns the intersection of the es and fm.encdesc
// by also taking into account what onions are stale
// on fm
/*static OnionLevelFieldMap
intersect(const EncSet & es, FieldMeta * fm) {
    OnionLevelFieldMap res;

    for (auto it : es.osl) {
        onion o = it.first;
        auto ed_it = fm->encdesc.olm.find(o);
        if ((ed_it != fm->encdesc.olm.end()) && (!fm->onions[o]->stale)) {
            //an onion to keep
            res[o] = LevelFieldPair(min(it.second.first, ed_it->second), fm);
        }
    }

    return res;
}
*/
/*
 * Actual item handlers.
 */
static void process_select_lex(st_select_lex *select_lex, Analysis & a);

static void optimize_select_lex(st_select_lex *select_lex, Analysis & a);

static st_select_lex * rewrite_select_lex(st_select_lex *select_lex, Analysis & a);

static class ANON : public CItemSubtypeIT<Item_field, Item::Type::FIELD_ITEM> {

    virtual RewritePlan * do_gather_type(Item_field *i, reason &tr, Analysis & a) const {
        LOG(cdb_v) << "FIELD_ITEM do_gather " << *i;

        string fieldname = i->field_name;
        string table = i->table_name;
	string fullname = fullName(fieldname, table);
        if (a.ps->mp && a.ps->mp->hasEncFor(fullname)) {
	    a.tmkm.encForVal[fullname] = "";
        }

        FieldMeta * fm = a.ps->schema->getFieldMeta(table, fieldname);

	EncSet es  = EncSet(fm);

	tr = reason(es, "is a field", i);

	return new RewritePlan(es, tr);

    }

    virtual Item *
    do_rewrite_type(Item_field *i,
		    const OLK & constr, const RewritePlan * rp,
		    Analysis & a) const
    {
        LOG(cdb_v) << "do_rewrite_type FIELD_ITEM " << *i;

		FieldMeta *fm = a.ps->schema->getFieldMeta(i->table_name, i->field_name);
		//assert(constr.key == fm);

		//check if we need onion adjustment
		if (constr.l < fm->encdesc.olm[constr.o]) {
			//need adjustment, throw exception
			throw OnionAdjustExcept(constr.o, fm, constr.l, i);
		}

		Item_field * res = make_item(i);

		if (!fm->isEncrypted()) { // Not encrypted
			return res;
		}

		// Encrypted item

		res->table_name = make_thd_string(anonymize_table_name(i->table_name, a));
		res->field_name = make_thd_string(fm->onions[constr.o]->onionname);

        return res;
    }
/*
    static OLK
    chooseProj(FieldMeta * fm) {
	SECLEVEL l;
	if (contains_get(fm->encdesc.olm, oDET, l)) {
	    return OLK(oDET, l, fm);
	}
	if (contains_get(fm->encdesc.olm, oOPE, l)) {
	    return OLK(oOPE, l, fm);
	}
	if (contains_get(fm->encdesc.olm, oAGG, l)) {
	    return OLK(oAGG, l, fm);
	}
	assert_s(false, "field " + fm->fname + " does not have any decryptable onions for projection");
	return OLK();
    }
*/

    //do we need do_rewrite_insert?
    virtual void
    do_rewrite_insert_type(Item_field *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
	assert(fm==NULL);
        fm = a.ps->schema->getFieldMeta(i->table_name, i->field_name);

	if (!fm->isEncrypted()) {
	    l.push_back(make_item(i, fm->fname));
	    return;
	}

	// Encrypted field

	Item_field * new_field = NULL;
        for (auto it = fm->onions.begin();
             it != fm->onions.end(); ++it) {
            string name = it->second->onionname;
			new_field = make_item(i, name);
			l.push_back(new_field);
        }
        if (fm->has_salt) {
            assert(!fm->salt_name.empty());
			assert(new_field); //need an anonymized field as template to create
			       //salt item
            l.push_back(make_item(new_field, fm->salt_name));
        }
    }

} ANON;

static class ANON : public CItemSubtypeIT<Item_string, Item::Type::STRING_ITEM> {
    virtual RewritePlan * do_gather_type(Item_string *i, reason &tr, Analysis & a) const {
        LOG(cdb_v) << " String item do_gather " << *i;
        /* constant strings are always ok */
        for (auto it = a.tmkm.encForVal.begin(); it != a.tmkm.encForVal.end(); it++) {
            if (it->second == "") {
                stringstream temp;
                temp << *i;
                it->second = temp.str();
            }
        }

	tr = reason(FULL_EncSet, "is a constant", i);
	return new RewritePlan(FULL_EncSet_Str, tr);

    }
    virtual Item * do_optimize_type(Item_string *i, Analysis & a) const {
        return i;
    }

    virtual Item * do_rewrite_type(Item_string *i,
				   const OLK & constr, const RewritePlan * rp,
				   Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type String item " << *i;

        return encrypt_item(i, constr, a);
    }

    virtual void
    do_rewrite_insert_type(Item_string *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
	if (!fm->isEncrypted()) {
	    l.push_back(make_item(i));
	    return;
	}

	// Encrypted

	uint64_t salt = 0;

	if (fm->has_salt) {
            salt = randomValue();
        } else {
            //TODO: need to use table salt in this case
        }

        encrypt_item_all_onions(i, fm, salt, l, a);

        if (fm->has_salt) {
            l.push_back(new Item_int((ulonglong) salt));
        }
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_num, Item::Type::INT_ITEM> {
    virtual RewritePlan * do_gather_type(Item_num *i, reason &tr, Analysis & a) const {
        LOG(cdb_v) << "CItemSubtypeIT (L966) num do_gather " << *i;
        /* constant ints are always ok */
        for (auto it = a.tmkm.encForVal.begin(); it != a.tmkm.encForVal.end(); it++) {
            if (it->second == "") {
                stringstream temp;
                temp << *i;
                it->second = temp.str();
            }
        }

	tr = reason(FULL_EncSet, "is a constant", i);
	return new RewritePlan(FULL_EncSet_Int, tr);

    }

    virtual Item * do_optimize_type(Item_num *i, Analysis & a) const {
        return i;
    }

    virtual Item * do_rewrite_type(Item_num *i,
				   const OLK & constr, const RewritePlan * rp,
				   Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type " << *i << endl;
        return encrypt_item(i, constr, a);
    }

    virtual void
    do_rewrite_insert_type(Item_num *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
	if (!fm->isEncrypted()) {
	    l.push_back(make_item((Item_int*)i));
	     return;
	}

	//Encrypted

        uint64_t salt = 0;
        if (fm->has_salt) {
            salt = randomValue();
        } else {
            //TODO raluca
            //need to use table salt in this case
        }

      	//encrypt for each onion
        for (auto it = fm->onions.begin(); it != fm->onions.end();it++) {
            l.push_back(encrypt_item_layers(i, it->first, it->second->layers, a, fm, salt));
        }

        if (fm->has_salt) {
             l.push_back(new Item_int((ulonglong) salt));
        }
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_decimal, Item::Type::DECIMAL_ITEM> {
    virtual RewritePlan * do_gather_type(Item_decimal *i, reason &tr, Analysis & a) const {
        LOG(cdb_v) << "CItemSubtypeIT (L1024) decimal do_gather " << *i;
	UNIMPLEMENTED;
        /* constant decimals are always ok */
        return NULL;
    }
        virtual Item * do_optimize_type(Item_decimal *i, Analysis & a) const {
        return i;
    }
    virtual Item * do_rewrite_type(Item_decimal *i,
				   const OLK & constr, const RewritePlan * rp,
				   Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type L1028";
        double n = i->val_real();
        char buf[sizeof(double) * 2];
        sprintf(buf, "%x", (unsigned int)n);
        // TODO(stephentu): Do some actual encryption of the double here
        return new Item_hex_string(buf, sizeof(buf));
    }
    virtual void
    do_rewrite_insert_type(Item_decimal *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
        assert(fm != NULL);
        double n = i->val_real();
        char buf[sizeof(double) * 2];
        sprintf(buf, "%x", (unsigned int)n);
        for (auto it = fm->onions.begin();
             it != fm->onions.end();
             ++it) {
            l.push_back(new Item_hex_string(buf, sizeof(buf)));
        }
        if (fm->has_salt) {
            l.push_back(new Item_hex_string(buf, sizeof(buf)));
        }
        //if no onions, add field as is
        if (l.empty()) {
            l.push_back(new Item_hex_string(buf, sizeof(buf)));
        }
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_neg, Item_func::Functype::NEG_FUNC> {
    virtual RewritePlan * do_gather_type(Item_func_neg *i, reason &tr, Analysis & a) const {
        return gather(i->arguments()[0], tr, a);
    }
    virtual Item * do_optimize_type(Item_func_neg *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_not, Item_func::Functype::NOT_FUNC> {
    virtual RewritePlan * do_gather_type(Item_func_not *i, reason &tr, Analysis & a) const {
        return gather(i->arguments()[0], tr, a);
    }
    virtual Item * do_optimize_type(Item_func_not *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_subselect, Item::Type::SUBSELECT_ITEM> {
    virtual RewritePlan * do_gather_type(Item_subselect *i, reason &tr, Analysis & a) const {
	/*
        st_select_lex *select_lex = i->get_select_lex();
        process_select_lex(select_lex, a);
        return tr.encset;*/
	UNIMPLEMENTED;
	return NULL;
    }
    virtual Item * do_optimize_type(Item_subselect *i, Analysis & a) const {
        optimize_select_lex(i->get_select_lex(), a);
        return i;
    }
} ANON;

extern const char str_in_optimizer[] = "<in_optimizer>";
static class ANON : public CItemSubtypeFN<Item_in_optimizer, str_in_optimizer> {
    virtual RewritePlan * do_gather_type(Item_in_optimizer *i, reason &tr, Analysis & a) const {
        LOG(cdb_v) << "CItemSubtypeFN (L1107) do_gather " << *i;

	UNIMPLEMENTED;
        //Item **args = i->arguments();
        //analyze(args[0], reason(EMPTY_EncSet, "in_opt", i, &tr), a);
        //analyze(args[1], reason(EMPTY_EncSet, "in_opt", i, &tr), a);
        return NULL;
    }
    virtual Item * do_optimize_type(Item_in_optimizer *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_cache, Item::Type::CACHE_ITEM> {
    virtual RewritePlan * do_gather_type(Item_cache *i, reason &tr, Analysis & a) const {
	/*
        Item *example = i->*rob<Item_cache, Item*, &Item_cache::example>::ptr();
        if (example)
            return gather(example, tr, a);
	    return tr.encset;*/
	UNIMPLEMENTED;
	return NULL;
    }
    virtual Item * do_optimize_type(Item_cache *i, Analysis & a) const {
        // TODO(stephentu): figure out how to use rob here
        return i;
    }
} ANON;


template<Item_func::Functype FT, class IT>
class CItemCompare : public CItemSubtypeFT<Item_func, FT> {
    virtual RewritePlan * do_gather_type(Item_func *i, reason &tr, Analysis & a) const {
	    LOG(cdb_v) << "CItemCompare (L1139) do_gather func " << *i;

        EncSet my_es;
	    string why = "";

        if (FT == Item_func::Functype::EQ_FUNC ||
            FT == Item_func::Functype::EQUAL_FUNC ||
            FT == Item_func::Functype::NE_FUNC) {
            my_es = EQ_EncSet;
	        why = "compare equality";
        } else {
            my_es = ORD_EncSet;
	        why = "compare order";
        }

	    Item ** args = i->arguments();
	    assert_s(i->argument_count() == 2, "expected two arguments for comparison");
        if (!args[0]->const_item() && !args[1]->const_item()) {
            why = why + "; join";
	        cerr << "join";
	        my_es = JOIN_EncSet;
	    }

	    return typical_gather(a, i, my_es, why, tr, false, PLAIN_EncSet);
    }

    virtual Item * do_optimize_type(Item_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }

    virtual Item * do_rewrite_type(Item_func *i, const OLK & constr,
				   const RewritePlan * rp, Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type Item_func " << *i << " constr " << constr;
	Item ** args = i->arguments();
	assert_s(i->argument_count() == 2, "compare function does not have two arguments as expected");
	IT *res = new IT(args[0], args[1]);
	rewrite_args_FN(res, constr, (const RewritePlanOneOLK *)rp, a);
        LOG(cdb_v) << "return 1171 " << *res;
        return res;
    }
};

static CItemCompare<Item_func::Functype::EQ_FUNC,    Item_func_eq>    ANON;
static CItemCompare<Item_func::Functype::EQUAL_FUNC, Item_func_equal> ANON;
static CItemCompare<Item_func::Functype::NE_FUNC,    Item_func_ne>    ANON;
static CItemCompare<Item_func::Functype::GT_FUNC,    Item_func_gt>    ANON;
static CItemCompare<Item_func::Functype::GE_FUNC,    Item_func_ge>    ANON;
static CItemCompare<Item_func::Functype::LT_FUNC,    Item_func_lt>    ANON;
static CItemCompare<Item_func::Functype::LE_FUNC,    Item_func_le>    ANON;

template<Item_func::Functype FT, class IT>
class CItemCond : public CItemSubtypeFT<Item_cond, FT> {
    virtual RewritePlan * do_gather_type(Item_cond *i, reason &tr, Analysis & a) const {
	/*   auto it = List_iterator<Item>(*i->argument_list());
        for (;;) {
            Item *argitem = it++;
            if (!argitem)
                break;
	    reason new_tr(tr.encset.intersect(EQ_EncSet), "and/or", i);
            RewritePlan * rp = gather(argitem, tr, a);
            if (!rp->es_out.contains(PLAIN_OLK))
                thrower() << "cannot obtain PLAIN for " << *argitem;
        }

        return rp;*/
	UNIMPLEMENTED;
    }

    virtual Item * do_optimize_type(Item_cond *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }

    virtual Item * do_rewrite_type(Item_cond *i,
				   const OLK & olk, const RewritePlan * rp, Analysis & a) const {
	List<Item> newlist;
	auto it = List_iterator<Item>(*i->argument_list());
	for (;;) {
	    Item *argitem = it++;
	    if (!argitem) {
		break;
	    }
	    newlist.push_back(rewrite(argitem, olk, a));
	}

	IT * res = new IT(newlist);
	return res;
    }
};

static CItemCond<Item_func::Functype::COND_AND_FUNC, Item_cond_and> ANON;
static CItemCond<Item_func::Functype::COND_OR_FUNC,  Item_cond_or>  ANON;

template<Item_func::Functype FT>
class CItemNullcheck : public CItemSubtypeFT<Item_bool_func, FT> {
    virtual RewritePlan * do_gather_type(Item_bool_func *i, reason &tr, Analysis & a) const {
	/*  Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(EMPTY_EncSet,  "nullcheck", i, &tr), a);
	    return tr.encset;*/
	UNIMPLEMENTED;
    }

    virtual Item * do_optimize_type(Item_bool_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }

};

static CItemNullcheck<Item_func::Functype::ISNULL_FUNC> ANON;
static CItemNullcheck<Item_func::Functype::ISNOTNULL_FUNC> ANON;

static class ANON : public CItemSubtypeFT<Item_func_get_system_var, Item_func::Functype::GSYSVAR_FUNC> {

    virtual RewritePlan * do_gather_type(Item_func_get_system_var *i, reason &tr, Analysis & a) const {
	reason r = reason(PLAIN_EncSet, "system var", i);
	return new RewritePlan(PLAIN_EncSet, r);
    }

    virtual Item * do_rewrite_type(Item_func_get_system_var * i,
	                           const OLK & constr, const RewritePlan * _rp,
	                           Analysis & a) const {
	return i;
    }
} ANON;

template<const char *NAME>
class CItemAdditive : public CItemSubtypeFN<Item_func_additive_op, NAME> {
    virtual RewritePlan * do_gather_type(Item_func_additive_op *i, reason &tr, Analysis & a) const {
	    return typical_gather(a, i, ADD_EncSet, "additive", tr, true);
    }
    virtual Item * do_optimize_type(Item_func_additive_op *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }

    virtual Item * do_rewrite_type(Item_func_additive_op *i,
				   const OLK & constr, const RewritePlan * _rp,
				   Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type Item_func_additive_op" << *i << " with constr " << constr;

	//rewrite children
	assert_s(i->argument_count() == 2, " expecting two arguments for additive operator ");
	Item **args = i->arguments();

	RewritePlanOneOLK * rp = (RewritePlanOneOLK *) _rp;

        cerr << "Rewrite plan is " << rp << "\n";

	Item * arg0 = itemTypes.do_rewrite(args[0],
					   rp->olk, rp->childr_rp[0], a);
	Item * arg1 = itemTypes.do_rewrite(args[1],
					   rp->olk, rp->childr_rp[1], a);

	EncLayer *el = getAssert(constr.key->onions, oAGG)->layers.back();
	assert_s(el->level() == SECLEVEL::HOM, "incorrect onion level on onion oHOM");
	return ((HOM*)el)->sumUDF(arg0, arg1);

	}
};

extern const char str_plus[] = "+";
static CItemAdditive<str_plus> ANON;

extern const char str_minus[] = "-";
static CItemAdditive<str_minus> ANON;

/*
* Implementation for SELECT x*val
*/
template<const char *NAME>
class CItemMultiplicative : public CItemSubtypeFN<Item_func_mul, NAME> {
    virtual RewritePlan * do_gather_type(Item_func_mul *i, reason &tr, Analysis & a) const {
		return typical_gather(a, i, PROD_EncSet, "multiplicative", tr, true);
    }
    virtual Item * do_optimize_type(Item_func_mul *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }

    virtual Item * do_rewrite_type(Item_func_mul *i,
				   const OLK & constr, const RewritePlan * _rp,
				   Analysis & a) const {
        LOG(cdb_v) << "do_rewrite_type Item_func_mul" << *i << " with constr " << constr; 

		//rewrite children
		assert_s(i->argument_count() == 2, " expecting two arguments for multiplicative operator ");
		Item **args = i->arguments();

		RewritePlanOneOLK * rp = (RewritePlanOneOLK *) _rp;

		cerr << "Rewrite plan is " << rp << "\n";

		Item * arg0 = itemTypes.do_rewrite(args[0],
						   rp->olk, rp->childr_rp[0], a);
		Item * arg1 = itemTypes.do_rewrite(args[1],
					   rp->olk, rp->childr_rp[1], a);

		EncLayer *el = getAssert(constr.key->onions, oELG)->layers.back();
		assert_s(el->level() == SECLEVEL::ELG, "incorrect onion level on onion oELG");
		return ((ELG*)el)->prodUDF(arg0, arg1); 
	}
};

extern const char str_mul[] = "*";
static CItemMultiplicative<str_mul> ANON;

template<const char *NAME>
class CItemMath : public CItemSubtypeFN<Item_func, NAME> {
    virtual RewritePlan * do_gather_type(Item_func *i, reason &tr, Analysis & a) const {
	/* Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(EMPTY_EncSet, "math", i, &tr), a);
	    return tr.encset;*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_div[] = "/";
static CItemMath<str_div> ANON;

extern const char str_idiv[] = "div";
static CItemMath<str_idiv> ANON;

extern const char str_sqrt[] = "sqrt";
static CItemMath<str_sqrt> ANON;

extern const char str_round[] = "round";
static CItemMath<str_round> ANON;

extern const char str_sin[] = "sin";
static CItemMath<str_sin> ANON;

extern const char str_cos[] = "cos";
static CItemMath<str_cos> ANON;

extern const char str_acos[] = "acos";
static CItemMath<str_acos> ANON;

extern const char str_pow[] = "pow";
static CItemMath<str_pow> ANON;

extern const char str_log[] = "log";
static CItemMath<str_log> ANON;

extern const char str_radians[] = "radians";
static CItemMath<str_radians> ANON;

extern const char str_if[] = "if";
static class ANON : public CItemSubtypeFN<Item_func_if, str_if> {
    virtual RewritePlan * do_gather_type(Item_func_if *i, reason &tr, Analysis & a) const {
/*
	Item **args = i->arguments();
        assert(i->argument_count() == 3);
        analyze(args[0], reason(tr.encset, "if_cond", i, &tr), a);
        analyze(args[1], reason(tr.encset, "true_branch", i, &tr), a);
        analyze(args[2], reason(tr.encset, "false_branch", i, &tr), a);
        return tr.encset;*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_if *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

extern const char str_nullif[] = "nullif";
static class ANON : public CItemSubtypeFN<Item_func_nullif, str_nullif> {
    virtual RewritePlan * do_gather_type(Item_func_nullif *i, reason &tr, Analysis & a) const {
	/*    Item **args = i->arguments();
        EncSet cur = EQ_EncSet;
        for (uint x = 0; x < i->argument_count(); x++)
            cur = gather(args[x], reason(cur, "nullif", i, &tr), a);
        return cur;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_nullif *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

extern const char str_coalesce[] = "coalesce";
static class ANON : public CItemSubtypeFN<Item_func_coalesce, str_coalesce> {
    virtual RewritePlan * do_gather_type(Item_func_coalesce *i, reason &tr, Analysis & a) const {
	/* Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], tr, a);
	    return tr.encset;*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_coalesce *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

extern const char str_case[] = "case";
static class ANON : public CItemSubtypeFN<Item_func_case, str_case> {
    virtual RewritePlan * do_gather_type(Item_func_case *i, reason &tr, Analysis & a) const {
	/*     Item **args = i->arguments();
        int first_expr_num = i->*rob<Item_func_case, int,
                &Item_func_case::first_expr_num>::ptr();
        int else_expr_num = i->*rob<Item_func_case, int,
                &Item_func_case::else_expr_num>::ptr();
        uint ncases = i->*rob<Item_func_case, uint,
                &Item_func_case::ncases>::ptr();

        if (first_expr_num >= 0)
            analyze(args[first_expr_num],
                    reason(EQ_EncSet, "case_first", i, &tr), a);
        if (else_expr_num >= 0)
            analyze(args[else_expr_num], tr, a);

        for (uint x = 0; x < ncases; x += 2) {
            if (first_expr_num < 0)
            analyze(args[x],
                    reason(EMPTY_EncSet, "case_nofirst", i, &tr), a);
            else
            analyze(args[x],
                    reason(EQ_EncSet, "case_w/first", i, &tr), a);
            analyze(args[x+1], tr, a);
        }
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_case *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *NAME>
class CItemStrconv : public CItemSubtypeFN<Item_str_conv, NAME> {
    virtual RewritePlan * do_gather_type(Item_str_conv *i, reason & tr, Analysis & a) const {
	/* Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(EMPTY_EncSet, "strconv", i, &tr), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_str_conv *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_lcase[] = "lcase";
static CItemStrconv<str_lcase> ANON;

extern const char str_ucase[] = "ucase";
static CItemStrconv<str_ucase> ANON;

extern const char str_length[] = "length";
static CItemStrconv<str_length> ANON;

extern const char str_char_length[] = "char_length";
static CItemStrconv<str_char_length> ANON;

extern const char str_substr[] = "substr";
static CItemStrconv<str_substr> ANON;

extern const char str_concat[] = "concat";
static CItemStrconv<str_concat> ANON;

extern const char str_concat_ws[] = "concat_ws";
static CItemStrconv<str_concat_ws> ANON;

extern const char str_md5[] = "md5";
static CItemStrconv<str_md5> ANON;

extern const char str_left[] = "left";
static CItemStrconv<str_left> ANON;

extern const char str_regexp[] = "regexp";
static CItemStrconv<str_regexp> ANON;

template<const char *NAME>
class CItemLeafFunc : public CItemSubtypeFN<Item_func, NAME> {
    virtual RewritePlan * do_gather_type(Item_func *i, reason &tr, Analysis & a) const {
	UNIMPLEMENTED;
    }
};

extern const char str_found_rows[] = "found_rows";
static CItemLeafFunc<str_found_rows> ANON;

extern const char str_last_insert_id[] = "last_insert_id";
static CItemLeafFunc<str_last_insert_id> ANON;

extern const char str_rand[] = "rand";
static CItemLeafFunc<str_rand> ANON;

extern const char str_database[] = "database";
static CItemLeafFunc<str_database> ANON;

static class ANON : public CItemSubtypeFT<Item_extract, Item_func::Functype::EXTRACT_FUNC> {
    virtual RewritePlan * do_gather_type(Item_extract *i, reason &tr, Analysis & a) const {
	/* analyze(i->arguments()[0], reason(EMPTY_EncSet, "extract", i, &tr), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_extract *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *NAME>
class CItemDateExtractFunc : public CItemSubtypeFN<Item_int_func, NAME> {
    virtual RewritePlan * do_gather_type(Item_int_func *i, reason &tr, Analysis & a) const {
        /*Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            // assuming we separately store different date components
            analyze(args[x], tr, a);
        }
        return tr.encset;*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_int_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_second[] = "second";
static CItemDateExtractFunc<str_second> ANON;

extern const char str_minute[] = "minute";
static CItemDateExtractFunc<str_minute> ANON;

extern const char str_hour[] = "hour";
static CItemDateExtractFunc<str_hour> ANON;

extern const char str_to_days[] = "to_days";
static CItemDateExtractFunc<str_to_days> ANON;

extern const char str_year[] = "year";
static CItemDateExtractFunc<str_year> ANON;

extern const char str_month[] = "month";
static CItemDateExtractFunc<str_month> ANON;

extern const char str_dayofmonth[] = "dayofmonth";
static CItemDateExtractFunc<str_dayofmonth> ANON;

extern const char str_unix_timestamp[] = "unix_timestamp";
static CItemDateExtractFunc<str_unix_timestamp> ANON;

extern const char str_date_add_interval[] = "date_add_interval";
static class ANON : public CItemSubtypeFN<Item_date_add_interval, str_date_add_interval> {
    virtual RewritePlan * do_gather_type(Item_date_add_interval *i, reason &tr, Analysis & a) const {
	/* Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            // XXX perhaps too conservative
            analyze(args[x], reason(EMPTY_EncSet, "date_add", i, &tr), a);
        }
        return tr.encset;
        */
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_date_add_interval *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *NAME>
class CItemDateNow : public CItemSubtypeFN<Item_func_now, NAME> {
    virtual RewritePlan * do_gather_type(Item_func_now *i, reason &tr, Analysis & a) const {
        UNIMPLEMENTED;
    }
};

extern const char str_now[] = "now";
static CItemDateNow<str_now> ANON;

extern const char str_utc_timestamp[] = "utc_timestamp";
static CItemDateNow<str_utc_timestamp> ANON;

extern const char str_sysdate[] = "sysdate";
static CItemDateNow<str_sysdate> ANON;

template<const char *NAME>
class CItemBitfunc : public CItemSubtypeFN<Item_func_bit, NAME> {
    virtual RewritePlan * do_gather_type(Item_func_bit *i, reason &tr, Analysis & a) const {
        /*Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(EMPTY_EncSet, "bitfunc", i, &tr), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_bit *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_bit_not[] = "~";
static CItemBitfunc<str_bit_not> ANON;

extern const char str_bit_or[] = "|";
static CItemBitfunc<str_bit_or> ANON;

extern const char str_bit_xor[] = "^";
static CItemBitfunc<str_bit_xor> ANON;

extern const char str_bit_and[] = "&";
static CItemBitfunc<str_bit_and> ANON;

static class ANON : public CItemSubtypeFT<Item_func_like, Item_func::Functype::LIKE_FUNC> {
    virtual RewritePlan * do_gather_type(Item_func_like *i, reason &tr,
					 Analysis & a) const {

	assert_s(false, "LIKE needs to be adapted to new RewritePlans");
	/*
	LOG(cdb_v) << "Item_func do_gather_type " << *i;

	Item **args = i->arguments();
	assert_s(i->argument_count() == 2, "expecting LIKE to have two arguments");

	if ((args[0]->type() == Item::Type::FIELD_ITEM) && (args[1]->type() == Item::Type::STRING_ITEM)) {

	    string s(args[1]->str_value.ptr(), args[1]->str_value.length());

	    if (s.find('%') == s.npos && s.find('_') == s.npos) {
                // some queries actually use LIKE as an equality check..
		return typical_gather(a, i, EQ_EncSet, "LIKE equality", tr, false, PLAIN_EncSet);

            } else {

		// XXX check if pattern is one we can support?

		reason r1;
		RewritePlan * rp1 = gather(args[0], r1, a);

		EncSet solution = rp1->es_out.intersect(Search_EncSet);

		if (solution.empty()) {
		    cerr << "cannot support " << i << " BECAUSE it needs any of " << Search_EncSet << "\n" \
			 << " but field only supports  " << rp1->es_out << "\n";
		}

		stringstream ss;
		ss << "like:'" << s << "'";
		tr = reason(PLAIN_EncSet, ss.str(), i);
		tr.add_child(r1);

		return new RewritePlan(PLAIN_OLK, solution.chooseOne(), tr);
            }
        } else {
            // we cannot support non-constant search patterns
	    assert_s(false, "we cannot support search patterns not of the form (field like const string)");
	    //for (uint x = 0; x < i->argument_count(); x++)
            //    analyze(args[x], reason(EMPTY_EncSet, "like-non-const", i, &tr), a);
        }


	*/
	return NULL;
    }
    virtual Item * do_optimize_type(Item_func_like *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
    virtual Item * do_rewrite_type(Item_func_like *i,
				   const OLK & constr, const RewritePlan *rp,
				   Analysis & a) const {
/*	LOG(cdb_v) << "Item_func_like do_rewrite_type " << *i;

	assert_s(i->argument_count() == 2, "expecting LIKE to have two arguements");
	Item **args = i->arguments();

	if ((args[0]->type() == Item::Type::FIELD_ITEM) && (args[1]->type() == Item::Type::STRING_ITEM)) {

	    string s(args[1]->str_value.ptr(), args[1]->str_value.length());

	    if (s.find('%') == s.npos && s.find('_') == s.npos) {
                // some queries actually use LIKE as an equality check..

		Item_func_like * res = new Item_func_like(args[0], args[1], NULL, false);
		do_rewrite_type_args(i, res, constr, a);

		return res;

            } else {
		// XXX check if pattern is one we can support?

		RewritePlan * plan = getAssert(a.itemRewritePlans, (Item*) i);
		auto childr_plan = getAssert(plan->plan, constr);
		OLK child_OLK = getAssert(childr_plan, args[0]);

		if (child_OLK == PLAIN_OLK) {
		    return new Item_func_like(args[0], args[1], NULL, false);
		}

		Item * field = itemTypes.do_rewrite(args[0], child_OLK, a);
		args[0]->name = NULL; //no alias

		Item * expr = args[1];
		FieldMeta * fm = child_OLK.key;

		EncLayer * el = getAssert(fm->onions, oSWP)->layers.back();
		assert_s(el->level() == SECLEVEL::SEARCH, "incorrect onion  level on onion oSWP");

		Item * res = ((Search *) el)->searchUDF(field, expr);
		cerr << "result is " << *res << "\n";

		return res;
            }
        }

	// we cannot support non-constant search patterns
	assert_s(false, "we cannot support search patterns not of the form (field like constant string)");
*/
	assert_s(false, "LIKE needs to be updated to new RewritePlan interface");
	return NULL;

    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func, Item_func::Functype::FUNC_SP> {
    void error(Item_func *i) const __attribute__((noreturn)) {
        thrower() << "unsupported store procedure call " << *i;
    }

    virtual RewritePlan * do_gather_type(Item_func *i, reason &tr, Analysis & a) const __attribute__((noreturn)) { error(i); }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_in, Item_func::Functype::IN_FUNC> {
    virtual RewritePlan * do_gather_type(Item_func_in *i, reason &tr, Analysis & a) const {
	/*  Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(EQ_EncSet, "in", i, &tr), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_in *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_in, Item_func::Functype::BETWEEN> {
    virtual RewritePlan * do_gather_type(Item_func_in *i, reason &tr, Analysis & a) const {
	/*  Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(ORD_EncSet, "between", i, &tr), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_in *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

//TODO: use this func in other places as well
/*static List<Item> *
getArgs(Item_func * itf) {
    List<Item> * res = new List<Item>();
    Item ** args = itf->arguments();
    for (uint j = 0; j < itf->argument_count(); j++)  {
	res->push_back(args[j]);
    }
    return res;
}
*/

template<const char *FN, class IT>
class CItemMinMax : public CItemSubtypeFN<Item_func_min_max, FN> {
    virtual RewritePlan * do_gather_type(Item_func_min_max *i, reason &tr, Analysis & a) const {
	Item **args = i->arguments();
        uint argcount = i->argument_count();
	if (argcount != 2) {
	    cerr << "expected two arguments in " << *i << "\n";
	    assert(false);
	}
	//at least one has to be a constant as we don't support join now
	assert_s(args[0]->const_item() || args[1]->const_item(), "ope join not yet implemented");

	reason r1, r2;
	RewritePlan ** childr_rp = new RewritePlan*[2];
	childr_rp[0] = gather(args[0], r1, a);
        childr_rp[1] = gather(args[1], r2, a);
	EncSet es1 = childr_rp[0]->es_out;
	EncSet es2 = childr_rp[1]->es_out;

	EncSet needed_es = ORD_EncSet;

	EncSet supported_es = needed_es.intersect(es1).intersect(es2);

	if (supported_es.empty()) {
	    cerr << "cannot support " << i << " BECAUSE it needs any of " << needed_es << "\n" \
		 << "BUT children only have (" << r1 << "\n" << r2 << ")\n";
	    assert(false);
	}

	EncSet out_es = es1.intersect(es2);

	tr = reason(out_es, "min_max func", i);
	tr.add_child(r1);
	tr.add_child(r2);

	//prepare rewrite plans
	return new RewritePlanOneOLK(out_es,
				     supported_es.chooseOne(),
				     childr_rp, tr);
    }
    virtual Item * do_optimize_type(Item_func_min_max *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }

    virtual Item * do_rewrite_type(Item_func_min_max *i,
				   const OLK & constr, const RewritePlan * _rp,
				   Analysis & a) const {
	RewritePlanOneOLK * rp = (RewritePlanOneOLK *) _rp;

	if (rp->olk == PLAIN_OLK) { // no change
	    return i;
	}

	// replace with IF( cond_arg0 cond cond_arg1, args0, args1)
	Item ** args = i->arguments();
	Item * cond_arg0 = itemTypes.do_rewrite(args[0],
						rp->olk, rp->childr_rp[0], a);
	Item * cond_arg1 = itemTypes.do_rewrite(args[1],
						rp->olk, rp->childr_rp[1], a);

	int cmp_sign = i->*rob<Item_func_min_max, int, &Item_func_min_max::cmp_sign>::ptr();

	Item * cond;
	if (cmp_sign) {
	    cond = new Item_func_gt(cond_arg0, cond_arg1);
	} else {
	    cond = new Item_func_lt(cond_arg0, cond_arg1);
	}

	return new Item_func_if(cond,
				itemTypes.do_rewrite(args[0], constr,
						     rp->childr_rp[0], a),
				itemTypes.do_rewrite(args[1], constr,
						     rp->childr_rp[1], a));
    }
};

//TODO: do we still need the file analyze.cc?

extern const char str_greatest[] = "greatest";
static CItemMinMax<str_greatest, Item_func_max> ANON;

extern const char str_least[] = "least";
static CItemMinMax<str_least, Item_func_min> ANON;


extern const char str_strcmp[] = "strcmp";
static class ANON : public CItemSubtypeFN<Item_func_strcmp, str_strcmp> {
    virtual RewritePlan * do_gather_type(Item_func_strcmp *i, reason &tr, Analysis & a) const {
        //cerr << "do_a_t Item_func_strcmp reason " << tr << "\n";
	/* Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], reason(EQ_EncSet, "strcmp", i, &tr), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_strcmp *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<Item_sum::Sumfunctype SFT>
class CItemCount : public CItemSubtypeST<Item_sum_count, SFT> {
    virtual RewritePlan * do_gather_type(Item_sum_count *i, reason &tr, Analysis & a) const {
	/*
        if (i->has_with_distinct()) {
	    reason new_tr(tr.encset.intersect(EQ_EncSet), "count distinct", i);
            EncSet e = gather(i->get_arg(0), new_tr, a);
            if (e.intersect(EQ_EncSet).empty())
                thrower() << "count distinct";
	}
	return PLAIN_EncSet;*/
	UNIMPLEMENTED;

    }
    virtual Item * do_rewrite_type(Item_sum_count *i,
				   const OLK & constr, const RewritePlan * rp,
				   Analysis & a) const {
/*	Item_sum_count * res = new Item_sum_count(current_thd, i);

	if (i->has_with_distinct()) {
	    rewrite_agg_args(res, a);
	}
	ItemMeta *im = getAssert(a.itemToMeta, (Item *)i);

	addToReturn(a.rmeta, a.pos++, im, false, i->name);

	return res;
*/
	UNIMPLEMENTED;
    }
};

static CItemCount<Item_sum::Sumfunctype::COUNT_FUNC> ANON;
static CItemCount<Item_sum::Sumfunctype::COUNT_DISTINCT_FUNC> ANON;

static void
check_if_empty(const EncSet & sol, Item * i, const EncSet & my_es, const reason & child_r) {
    if (sol.empty()) {
	cerr << "current crypto schemes do not support this query \n" \
	     << "BECAUSE " << i << " NEEDS " << my_es << "\n"	      \
	     << "AND children have " << child_r << "\n";
	assert(false);
    }
}

template<Item_sum::Sumfunctype SFT, class IT>
class CItemChooseOrder : public CItemSubtypeST<Item_sum_hybrid, SFT> {
    virtual RewritePlan * do_gather_type(Item_sum_hybrid *i, reason &tr, Analysis & a) const {
      assert(i->get_arg_count() == 1);
      Item *child = i->get_arg(0);
      RewritePlan **child_rp = new RewritePlan*[1];
      reason r;
      child_rp[0] = gather(child, r, a);
      EncSet es = child_rp[0]->es_out;
      EncSet needed = ORD_EncSet;
      EncSet supported = needed.intersect(es);
      check_if_empty(supported, i, needed, r);
      OLK olk = supported.chooseOne();
      EncSet out = EncSet(olk);
      tr= reason(out, "min/max", i);
      return new RewritePlanOneOLK(out, olk, child_rp, tr);
    }

    virtual Item * do_rewrite_type(Item_sum_hybrid *i,
           const OLK & constr, const RewritePlan * rp,
           Analysis & a) const {
      list<Item *> args =
        rewrite_agg_args(i, constr, (RewritePlanOneOLK *)rp, a, 1);
      return new IT(args.front());
    }
};

static CItemChooseOrder<Item_sum::Sumfunctype::MIN_FUNC, Item_sum_min> ANON;
static CItemChooseOrder<Item_sum::Sumfunctype::MAX_FUNC, Item_sum_max> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemSum : public CItemSubtypeST<Item_sum_sum, SFT> {
    virtual RewritePlan * do_gather_type(Item_sum_sum *i, reason &tr, Analysis & a) const    {
        LOG(cdb_v) << "gather Item_sum_sum " << *i;
        assert_s(i->get_arg_count() == 1, "expected one argument for sum");
        Item * child_item = i->get_arg(0);
        reason child_r;
        RewritePlan ** childr_rp = new RewritePlan*[1];
        RewritePlan * child_rp = gather(child_item, child_r, a);
        childr_rp[0] = child_rp;
        EncSet child_es = child_rp->es_out;

        if (i->has_with_distinct()) {
            UNIMPLEMENTED;
        }

        EncSet my_es = ADD_EncSet;

        EncSet solution = my_es.intersect(child_es);

        check_if_empty(solution, i, my_es, child_r);

        OLK olk = solution.chooseOne();

        EncSet return_es = EncSet(olk);
        tr = reason(return_es, "summation", i);

        return new RewritePlanOneOLK(return_es, olk, childr_rp, tr); ;
    }

    virtual Item * do_rewrite_type(Item_sum_sum * i,
				   const OLK & constr, const RewritePlan * rp,
				   Analysis & a) const {

	    LOG(cdb_v) << "Item_sum_sum rewrite " << *i;

	    list<Item *> args = rewrite_agg_args(i, constr, (RewritePlanOneOLK *)rp, a, 1);

	    FieldMeta * fm = constr.key;
	    EncLayer * el = getAssert(fm->onions, oAGG, "onion oAGG not in onions")->layers.back();
	    assert_s(el->level() == SECLEVEL::HOM, "incorrect onion level on onion oHOM");
	    return ((HOM *)el)->sumUDA(args.front());

    }
};

//TODO: field OPE should not be blob for text either

static CItemSum<Item_sum::Sumfunctype::SUM_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::SUM_DISTINCT_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::AVG_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::AVG_DISTINCT_FUNC> ANON;

static class ANON : public CItemSubtypeST<Item_sum_bit, Item_sum::Sumfunctype::SUM_BIT_FUNC> {
    virtual RewritePlan * do_gather_type(Item_sum_bit *i, reason &tr, Analysis & a) const {
	/* LOG(cdb_v) << "do_a_t Item_sum_bit reason " << tr;
        analyze(i->get_arg(0), reason(EMPTY_EncSet, "bitagg", i, &tr, false), a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
} ANON;

static class ANON : public CItemSubtypeST<Item_func_group_concat, Item_sum::Sumfunctype::GROUP_CONCAT_FUNC> {
    virtual RewritePlan * do_gather_type(Item_func_group_concat *i, reason &tr, Analysis & a) const {
	/*  LOG(cdb_v) << "do_a_t Item_func_group reason " << tr;
        uint arg_count_field = i->*rob<Item_func_group_concat, uint,
                &Item_func_group_concat::arg_count_field>::ptr();
        for (uint x = 0; x < arg_count_field; x++) {
            // XXX could perform in the proxy..
            analyze(i->get_arg(x), reason(EMPTY_EncSet, "group_concat", i, &tr), a);
        }

        // XXX order, unused in trace queries..
        return tr.encset;
    */
	UNIMPLEMENTED;
    }
    // TODO(stephentu): figure out how to rob the arg fields for optimization
} ANON;

static class ANON : public CItemSubtypeFT<Item_char_typecast, Item_func::Functype::CHAR_TYPECAST_FUNC> {
    virtual RewritePlan * do_gather_type(Item_char_typecast *i, reason &tr, Analysis & a) const {
        thrower() << "what does Item_char_typecast do?";
        UNIMPLEMENTED;
    }
} ANON;

extern const char str_cast_as_signed[] = "cast_as_signed";
static class ANON : public CItemSubtypeFN<Item_func_signed, str_cast_as_signed> {
    virtual RewritePlan * do_gather_type(Item_func_signed *i, reason &tr, Analysis & a) const {
        /*LOG(cdb_v) << "do_a_t Item_func_signed reason " << tr;
        analyze(i->arguments()[0], tr, a);
        return tr.encset;
	*/
	UNIMPLEMENTED;
    }
    virtual Item * do_optimize_type(Item_func_signed *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_ref, Item::Type::REF_ITEM> {
    virtual RewritePlan * do_gather_type(Item_ref *i, reason &tr, Analysis & a) const {
        LOG(cdb_v) << "do_a_t Item_ref reason " << tr;
	/* if (i->ref) {
            analyze(*i->ref, tr, a);
            return tr.encset;
        } else {
            thrower() << "how to resolve Item_ref::ref?";
            UNIMPLEMENTED;
	    }*/
	UNIMPLEMENTED;
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_null, Item::Type::NULL_ITEM> {
    virtual RewritePlan * do_gather_type(Item_null *i, reason &tr, Analysis & a) const {
	UNIMPLEMENTED;
        //return FULL_EncSet;
    }
} ANON;


/*
 * Some helper functions.
 */

static void
optimize_select_lex(st_select_lex *select_lex, Analysis & a)
{
    auto item_it = List_iterator<Item>(select_lex->item_list);
    for (;;) {
        if (!item_it++)
            break;
        optimize(item_it.ref(), a);
    }

    if (select_lex->where)
        optimize(&select_lex->where, a);

    if (select_lex->join &&
        select_lex->join->conds &&
        select_lex->where != select_lex->join->conds)
        optimize(&select_lex->join->conds, a);

    if (select_lex->having)
        optimize(&select_lex->having, a);

    for (ORDER *o = select_lex->group_list.first; o; o = o->next)
        optimize(o->item, a);
    for (ORDER *o = select_lex->order_list.first; o; o = o->next)
        optimize(o->item, a);
}

static void
process_order(Analysis & a, SQL_I_List<ORDER> & lst) {

    for (ORDER *o = lst.first; o; o = o->next) {
	reason r;
	gather(*o->item, r, a);
    }

}

//TODO: not clear how these process_*_lex and rewrite_*_lex overlap, cleanup
static void
process_filters_lex(st_select_lex * select_lex, Analysis & a) {

    if (select_lex->where) {
	analyze(select_lex->where, a);
    }

    /*if (select_lex->join &&
        select_lex->join->conds &&
        select_lex->where != select_lex->join->conds)
        analyze(select_lex->join->conds, reason(FULL_EncSet, "join->conds", select_lex->join->conds, 0), a);*/

    if (select_lex->having)
        analyze(select_lex->having, a);

    process_order(a, select_lex->group_list);
    process_order(a, select_lex->order_list);

}


static void
process_select_lex(st_select_lex *select_lex, Analysis & a)
{
    //select clause
    auto item_it = List_iterator<Item>(select_lex->item_list);
    for (;;) {
        Item *item = item_it++;
        if (!item)
            break;

        analyze(item, a);
    }

    process_filters_lex(select_lex, a);
}

static void
rewrite_order(Analysis & a, SQL_I_List<ORDER> & lst,
	      const EncSet & constr, const string & name) {
    ORDER * prev = NULL;
    for (ORDER *o = lst.first; o; o = o->next) {
	Item * i = *o->item;
	RewritePlan * rp = getAssert(a.rewritePlans, i);
	assert(rp);
	EncSet es = constr.intersect(rp->es_out);
	if (es.empty()) {
	    cerr << " cannot support query because " << name << " item " << i << " needs to output any of " << constr << "\n" \
		 << " BUT it can only output " << rp->es_out << " BECAUSE " << "(" << rp->r << ")\n";
	    assert(false);
	}
	OLK olk = es.chooseOne();

	Item * new_item = itemTypes.do_rewrite(*o->item, olk, rp, a);
	ORDER * neworder = make_order(o, new_item);
	if (prev == NULL) {
	    lst = *oneElemList(neworder);
	} else {
	    prev->next = neworder;
	}
	prev = neworder;
    }

}

static st_select_lex *
rewrite_filters_lex(st_select_lex * select_lex, Analysis & a) {

    st_select_lex * new_select_lex = copy(select_lex);

    if (select_lex->where) {
        set_where(new_select_lex, rewrite(select_lex->where, PLAIN_OLK, a));
    }
    //  if (select_lex->join &&
	//     select_lex->join->conds &&
    //    select_lex->where != select_lex->join->conds) {
	//cerr << "select_lex join conds " << select_lex->join->conds << "\n";
	//rewrite(&select_lex->join->conds, a);
    //}

    if (select_lex->having)
        new_select_lex->having = rewrite(select_lex->having, PLAIN_OLK, a);

    rewrite_order(a, new_select_lex->group_list, EQ_EncSet, "group by");
    rewrite_order(a, new_select_lex->order_list, ORD_EncSet, "order by");

    return new_select_lex;
}

static bool
needsSalt(OLK olk) {
    return olk.key && olk.key->has_salt && needsSalt(olk.l);
}

static void
rewrite_proj(Item * i, const RewritePlan * rp, Analysis & a, List<Item> & newList)
{
    OLK olk = rp->es_out.chooseOne();
    Item *ir = rewrite(i, olk, a);
    newList.push_back(ir);
    bool use_salt = needsSalt(olk);

    addToReturn(a.rmeta, a.pos++, olk, use_salt, i->name);

    if (use_salt) {
        newList.push_back(make_item((Item_field*) ir, olk.key->salt_name));
        addSaltToReturn(a.rmeta, a.pos++);
    }
}

static st_select_lex *
rewrite_select_lex(st_select_lex *select_lex, Analysis & a)
{
    st_select_lex * new_select_lex = copy(select_lex);

    LOG(cdb_v) << "rewrite select lex input is " << *select_lex;
    auto item_it = List_iterator<Item>(select_lex->item_list);

    List<Item> newList;
    for (;;) {
        Item *item = item_it++;
        if (!item)
            break;
        LOG(cdb_v) << "rewrite_select_lex " << *item << " with name " << item->name;
	rewrite_proj(item, getAssert(a.rewritePlans, item), a, newList);
    }

    // TODO(stephentu): investigate whether or not this is a memory leak
    new_select_lex->item_list = newList;

    return rewrite_filters_lex(new_select_lex, a);
}

static void
optimize_table_list(List<TABLE_LIST> *tll, Analysis &a)
{
    List_iterator<TABLE_LIST> join_it(*tll);
    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t)
            break;

        if (t->nested_join) {
            optimize_table_list(&t->nested_join->join_list, a);
            return;
        }

        if (t->on_expr)
            optimize(&t->on_expr, a);

        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            optimize_select_lex(u->first_select(), a);
        }
    }
}

static void
process_table_list(List<TABLE_LIST> *tll, Analysis & a)
{
    /*
     * later, need to rewrite different joins, e.g.
     * SELECT g2_ChildEntity.g_id, IF(ai0.g_id IS NULL, 1, 0) AS albumsFirst, g2_Item.g_originationTimestamp FROM g2_ChildEntity LEFT JOIN g2_AlbumItem AS ai0 ON g2_ChildEntity.g_id = ai0.g_id INNER JOIN g2_Item ON g2_ChildEntity.g_id = g2_Item.g_id INNER JOIN g2_AccessSubscriberMap ON g2_ChildEntity.g_id = g2_AccessSubscriberMap.g_itemId ...
     */

    List_iterator<TABLE_LIST> join_it(*tll);
    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t)
            break;

        if (t->nested_join) {
            process_table_list(&t->nested_join->join_list, a);
            return;
        }

        if (t->on_expr)
            analyze(t->on_expr, a);

        //std::string db(t->db, t->db_length);
        //std::string table_name(t->table_name, t->table_name_length);
        //std::string alias(t->alias);

        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            /*
             * Not quite right, in terms of softness:
             * should really come from the items that eventually
             * reference columns in this derived table.
             */

            process_select_lex(u->first_select(), a);
        }
    }
}

static inline TABLE_LIST *
rewrite_table_list(TABLE_LIST *t, Analysis &a)
{
    TABLE_LIST * new_t = copy(t);
    string anon_name = anonymize_table_name(string(t->table_name,
                                                   t->table_name_length), a);
    new_t->table_name = make_thd_string(anon_name, &new_t->table_name_length);
    new_t->alias = make_thd_string(anon_name);
    new_t->next_local = NULL;
    return new_t;
}


static SQL_I_List<TABLE_LIST>
rewrite_table_list(SQL_I_List<TABLE_LIST> tlist, Analysis &a)
{
    if (!tlist.elements) {
	return SQL_I_List<TABLE_LIST>();
    }
    TABLE_LIST * tl = rewrite_table_list(tlist.first, a);

    SQL_I_List<TABLE_LIST> * new_tlist = oneElemList<TABLE_LIST>(tl);

    TABLE_LIST * prev = tl;
    for (TABLE_LIST *tbl = tlist.first->next_local;
	 tbl; tbl = tbl->next_local) {
	TABLE_LIST * new_tbl = rewrite_table_list(tbl, a);
	prev->next_local = new_tbl;
	prev = new_tbl;
    }
    prev->next_local = NULL;

    return *new_tlist;
}


static List<TABLE_LIST>
rewrite_table_list(List<TABLE_LIST> tll, Analysis & a)
{
    List<TABLE_LIST> * new_tll = new List<TABLE_LIST>();

    List_iterator<TABLE_LIST> join_it(tll);

    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t) {
	    break;
	}

        TABLE_LIST * new_t = rewrite_table_list(t, a);
	new_tll->push_back(new_t);

        if (t->nested_join) {
            new_t->nested_join->join_list = rewrite_table_list(t->nested_join->join_list, a);
            return *new_tll;
        }
/*
        if (t->on_expr) {
            new_t->on_expr = rewrite(t->on_expr, a);
	}
*/
	/* TODO: derived tables
        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            rewrite_select_lex(u->first_select(), a);
        }
	*/
    }

    return *new_tll;
}


// If mkey == NULL, the field is not encrypted
static void
init_onions_layout(AES_KEY * mKey, FieldMeta * fm, uint index, Create_field * cf, onionlayout ol) {

    fm->onions.clear();
    fm->encdesc.clear();

    for (auto it: ol) {
        onion o = it.first;
        OnionMeta * om = new OnionMeta();
        fm->onions[o] = om;

        om->onionname = anonymizeFieldName(index, o, fm->fname, false);

        if (mKey) {
            //generate enclayers for encrypted field
            for (auto l: it.second) {
                PRNG * key;
		key = getLayerKey(mKey, fullName(om->onionname, fm->tm->anonTableName), l);

                om->layers.push_back(EncLayerFactory::encLayer(o, l, cf, key));
            }
        }

        LOG(cdb_v) << "adding onion layer " << om->onionname << " for " << fm->fname;

        //set outer layer
        fm->encdesc.olm[o] = it.second.back();
    }
}

static void
init_onions(AES_KEY * mKey, FieldMeta * fm, Create_field * cf, uint index = 0) {
    if (!mKey) {
        // unencrypted field
        init_onions_layout(NULL, fm, 0, cf, PLAIN_ONION_LAYOUT);
        fm->has_salt = false;
        return;
    }

    // Encrypted field

    fm->has_salt = true;
    fm->salt_name = getFieldSalt(index, fm->tm->anonTableName);

    if (IsMySQLTypeNumeric(cf->sql_type)) {
        init_onions_layout(mKey, fm, index, cf, NUM_ONION_LAYOUT);
    } else {
        init_onions_layout(mKey, fm, index, cf, STR_ONION_LAYOUT);
    }
}

//XXX temporary hack until I've worked out how to set the AGG key in mp
static void
init_onions_mp(AES_KEY * mKey, FieldMeta * fm, Create_field * cf, uint index) {
    if (IsMySQLTypeNumeric(cf->sql_type)) {
        init_onions_layout(mKey, fm, index, cf, MP_NUM_ONION_LAYOUT);
    } else {
        init_onions_layout(mKey, fm, index, cf, STR_ONION_LAYOUT);
    }
}

static void
check_table_not_exists(Analysis & a, LEX * lex, string table) {
    auto it = a.ps->schema->tableMetaMap.find(table);
    if (it != a.ps->schema->tableMetaMap.end()) {
        if (!(lex->create_info.options & HA_LEX_CREATE_IF_NOT_EXISTS)) {
            LOG(warn) << "ERROR: Table exists. Embedded DB possibly"
		"out of sync with regular DB (or, just programmer error)";
        }
        return;
    }
}

static void
add_table(Analysis & a, const string & table, LEX *lex, bool encByDefault) {
    assert(lex->sql_command == SQLCOM_CREATE_TABLE);

    LOG(cdb_v) << "add_table encByDefault " << encByDefault;

    check_table_not_exists(a, lex, table);

    TableMeta *tm = new TableMeta();
    a.ps->schema->tableMetaMap[table] = tm;

    if (encByDefault) { //anonymize name
	// such increment may cause problem with multiple proxies
        tm->tableNo = a.ps->schema->totalTables++;
        tm->anonTableName = anonymizeTableName(tm->tableNo, table);
    } else {
        tm->anonTableName = table;
    }

    uint index =  0;
    for (auto it = List_iterator<Create_field>(lex->alter_info.create_list);;) {
        Create_field * field = it++;

        if (!field) {
            break;
        }

        FieldMeta * fm = new FieldMeta();

        fm->tm            = tm;
        fm->sql_field     = field->clone(current_thd->mem_root);
        fm->fname         = string(fm->sql_field->field_name);
        fm->index         = index;

        if (encByDefault) {
            init_onions(a.ps->masterKey, fm, field, index);
        } else {
            init_onions(NULL, fm, field);
        }

        assert(tm->fieldMetaMap.find(fm->fname) == tm->fieldMetaMap.end());
        tm->fieldMetaMap[fm->fname] = fm;
        tm->fieldNames.push_back(fm->fname);//TODO: do we need fieldNames?

        index++;

    }

}

//TODO: no need to pass create_field to this
static void rewrite_create_field(const string &table_name,
                                 Create_field *f,
                                 Analysis &a,
                                 vector<Create_field *> &l)
{
    LOG(cdb_v) << "in rewrite create field for " << *f;

    FieldMeta *fm = a.ps->schema->getFieldMeta(table_name, f->field_name);

    if (!fm->isEncrypted()) {
        // Unencrypted field
        l.push_back(f);
        return;
    }

    // Encrypted field

    //check if field is not encrypted
    if (fm->onions.empty()) {
        l.push_back(f);
        //cerr << "onions were empty" << endl;
        return;
    }

    // create each onion column
    for (auto oit = fm->onions.begin();
         oit != fm->onions.end();
         ++oit) {
	EncLayer * last_layer = oit->second->layers.back();
	//create field with anonymous name
	Create_field * new_cf = last_layer->newCreateField(oit->second->onionname.c_str());

        l.push_back(new_cf);
    }

    // create salt column
    if (fm->has_salt) {
        //cerr << fm->salt_name << endl;
        assert(!fm->salt_name.empty());
        THD *thd         = current_thd;
        Create_field *f0 = f->clone(thd->mem_root);
        f0->field_name   = thd->strdup(fm->salt_name.c_str());
	f0->flags = f0->flags | UNSIGNED_FLAG;//salt is unsigned
        f0->sql_type     = MYSQL_TYPE_LONGLONG;
	f0->length       = 8;
        l.push_back(f0);
    }
}

static void rewrite_key(const string &table_name,
                        Key *k,
                        Analysis &a,
                        vector<Key*> &l)
{
    //TODO
    l.push_back(k);
}


static void
create_table_embedded(Connect * e_conn, const string & cur_db,
    const string & create_q) {

    assert(e_conn->execute("create database if not exists " + cur_db + ";"));

    assert(e_conn->execute("use " + cur_db + ";"));
    assert(e_conn->execute(create_q));
}

/*
 * Analyzes create query.
 * Updates encrypted schema info.
 *
 */
static void
process_create_lex(LEX * lex, Analysis & a,
		   bool encByDefault, const string & cur_db)
{
    const string &table =
        lex->select_lex.table_list.first->table_name;
    //create table in embedded db
    //TODO: temporary hack!
    stringstream q;
    q << *lex;
    create_table_embedded(a.ps->e_conn, cur_db, q.str());
    LOG(cdb_v) << "table is " << table << " and encByDefault is " << encByDefault << " and true is " << true;
    add_table(a, table, lex, encByDefault);
}

static LEX *
rewrite_create_lex(LEX *lex, Analysis &a)
{
    LEX * new_lex = copy(lex);

    // table name
    const string &table =
        lex->select_lex.table_list.first->table_name;

    new_lex->select_lex.table_list =
	rewrite_table_list(lex->select_lex.table_list, a);

    //TODO: support for "create table like"
    if (lex->create_info.options & HA_LEX_CREATE_TABLE_LIKE) {
        cryptdb_err() << "No support for create table like yet. " <<
                   "If you see this, please implement me";
    } else {
        // TODO(stephentu): template this pattern away
        // (borrowed from rewrite_select_lex())
        auto cl_it = List_iterator<Create_field>(lex->alter_info.create_list);
        List<Create_field> newList;
        for (;;) {
            Create_field *cf = cl_it++;
            if (!cf)
                break;
            vector<Create_field *> l;
            rewrite_create_field(table, cf, a, l);
            for (auto it = l.begin(); it != l.end(); ++it) {
                newList.push_back(*it);
            }
        }
        new_lex->alter_info.create_list = newList;

        auto k_it = List_iterator<Key>(lex->alter_info.key_list);

        List<Key> newList0;
        for (;;) {
            Key *k = k_it++;
            if (!k)
                break;
            vector<Key *> l;
            rewrite_key(table, k, a, l);
            for (auto it = l.begin(); it != l.end(); ++it) {
                newList0.push_back(*it);
            }
        }
        new_lex->alter_info.key_list = newList0;
    }

    return new_lex;
}

static void
mp_update_init(LEX *lex, Analysis &a)
{
    if (!a.ps->mp) {return;}
    auto it = List_iterator<Item>(lex->select_lex.item_list);
    for (;;) {
        Item_field *i = (Item_field *) it++;
        if (!i) {
            break;
        }
        string fname = fullName(i->field_name, i->table_name);
        LOG(cdb_v) << fname;
        if (a.ps->mp->hasEncFor(fname)) {
            assert_s(false, "cannot update changes to access tree");
	    }
    }
}

static void
stalefy(FieldMeta * fm, const EncSet &  es) {
    for (auto o_l : fm->encdesc.olm) {
        onion o = o_l.first;
        if (es.osl.find(o) == es.osl.end()) {
            fm->onions[o]->stale = true;
        }
    }
}

static LEX *
rewrite_update_lex(LEX *lex, Analysis &a)
{
    LEX * new_lex = copy(lex);

    LOG(cdb_v) << "rewriting update \n";

    assert_s(lex->select_lex.item_list.head(), "update needs to have item_list");

    // multi-princ init
    mp_update_init(lex, a);

    // Rewrite table name
    new_lex->select_lex.top_join_list =
	rewrite_table_list(lex->select_lex.top_join_list, a);

    // Rewrite filters
    set_select_lex(new_lex, rewrite_filters_lex(&new_lex->select_lex, a));

    // Rewrite SET values
    assert(lex->select_lex.item_list.head());
    assert(lex->value_list.head());

    List<Item> res_items, res_vals;

    auto fd_it = List_iterator<Item>(lex->select_lex.item_list);
    auto val_it = List_iterator<Item>(lex->value_list);

    //TODO: need to make stale certain onions and not allow operations
    // to those onions any more; reset this after an update set

    // Look through all pairs in set: fd = val
    for (;;) {
        Item * i = fd_it++;
        if (!i) {
            break;
        }
        assert(i->type() == Item::FIELD_ITEM);
        Item_field * fd = static_cast<Item_field*>(i);

        FieldMeta * fm = a.ps->schema->getFieldMeta(fd->table_name, fd->field_name);

	Item * val = val_it++;
	assert(val != NULL);

	if (!fm->isEncrypted()) { // not encrypted field
	    res_items.push_back(i);
	    res_vals.push_back(val);
	    continue;
	}

	// Encrypted field

	RewritePlan * rp = getAssert(a.rewritePlans, val);
	EncSet r_es = rp->es_out.intersect(EncSet(fm));
	if (r_es.empty()) {
	    cerr << "update cannot be performed BECAUSE " << i << " supports " << fm->encdesc << "\n BUT " \
		 << val << " can only provide " << rp->es_out << " BECAUSE " << rp->r << "\n";
	    assert(false);
	}

        // Determine salt for field
	bool add_salt = false;
        if (fm->has_salt) {
            auto it_salt = a.salts.find(fm);
            if ((it_salt == a.salts.end()) && needsSalt(r_es)) {
		add_salt = true;
                salt_type salt = randomValue();
                a.salts[fm] = salt;
            }
        }

	Item * rew_fd = NULL;

        // Rewrite field-value pair for every onion possible
        for (auto pair : r_es.osl) {
	    OLK olk = {pair.first, pair.second.first, fm};
            res_items.push_back(rew_fd = itemTypes.do_rewrite(i, olk,
							      getAssert(a.rewritePlans, i), a));
            res_vals.push_back(itemTypes.do_rewrite(val, olk,
						    getAssert(a.rewritePlans, i), a));
        }

        // Make stale all onions that were not updated
        stalefy(fm, r_es);

	// Add the salt field
        if (add_salt) {
            salt_type salt = a.salts[fm];
	    assert(rew_fd);
            res_items.push_back(make_item((Item_field *)rew_fd, fm->salt_name));
            res_vals.push_back(new Item_int((ulonglong) salt));
        }

    }

    //TODO: cleanup old item and value list

    new_lex->select_lex.item_list = res_items;
    new_lex->value_list = res_vals;

    return new_lex;
}

static void
mp_insert_init(LEX *lex, Analysis &a)
{
    if (!a.ps->mp) {return; }
    //if this is MultiPrinc, insert may need keys; certainly needs to update AccMan
    a.tmkm.processingQuery = true;
    a.ps->mp->insertLex(lex, a.ps->schema, a.tmkm);
}

static LEX *
rewrite_insert_lex(LEX *lex, Analysis &a)
{
    LEX * new_lex = copy(lex);

    mp_insert_init(lex, a);

    const string &table =
            lex->select_lex.table_list.first->table_name;

    //rewrite table name
    new_lex->select_lex.table_list.first = rewrite_table_list(lex->select_lex.table_list.first, a);

    // fields
    vector<FieldMeta *> fmVec;
    if (lex->field_list.head()) {
        auto it = List_iterator<Item>(lex->field_list);
        List<Item> newList;
        for (;;) {
            Item *i = it++;
            if (!i)
                break;
            assert(i->type() == Item::FIELD_ITEM);
            Item_field *ifd = static_cast<Item_field*>(i);
            //cerr << "field " << ifd->table_name << "." << ifd->field_name << endl;
            fmVec.push_back(a.ps->schema->getFieldMeta(ifd->table_name, ifd->field_name));
            vector<Item *> l;
            itemTypes.do_rewrite_insert(i, a, l, NULL);
            for (auto it0 = l.begin(); it0 != l.end(); ++it0) {
                newList.push_back(*it0);
            }
        }
        new_lex->field_list = newList;
    }

    if (fmVec.empty()) {
        // use the table order now
	auto itt = a.ps->schema->tableMetaMap.find(table);
	assert(itt != a.ps->schema->tableMetaMap.end());

        TableMeta *tm = itt->second;
        //keep fields in order
        for (auto it0 = tm->fieldNames.begin(); it0 != tm->fieldNames.end(); it0++) {
            fmVec.push_back(tm->fieldMetaMap[*it0]);
        }
    }

    // values
    if (lex->many_values.head()) {
        auto it = List_iterator<List_item>(lex->many_values);
        List<List_item> newList;
        for (;;) {
            List_item *li = it++;
            if (!li)
                break;
            assert(li->elements == fmVec.size());
            List<Item> *newList0 = new List<Item>();
            auto it0 = List_iterator<Item>(*li);
            auto fmVecIt = fmVec.begin();
            for (;;) {
                Item *i = it0++;
                if (!i)
                    break;
                vector<Item *> l;
                itemTypes.do_rewrite_insert(i, a, l, *fmVecIt);
                for (auto it1 = l.begin(); it1 != l.end(); ++it1) {
                    newList0->push_back(*it1);
                    /*String s;
                    (*it1)->print(&s, QT_ORDINARY);
                    cerr << s << endl;*/
                }
                ++fmVecIt;
            }
            newList.push_back(newList0);
        }
        new_lex->many_values = newList;
    }

    return new_lex;
}

static void
process_update_lex(LEX * lex, Analysis & a) {

    if (lex->select_lex.item_list.head()) {
	assert(lex->value_list.head());

	auto fd_it = List_iterator<Item>(lex->select_lex.item_list);
	auto val_it = List_iterator<Item>(lex->value_list);

        for (;;) {
            Item *i = fd_it++;
	    Item * val = val_it++;
	    if (!i)
                break;
	    assert(val != NULL);
	    assert(i->type() == Item::FIELD_ITEM);
	    Item_field *ifd = static_cast<Item_field*>(i);
	    analyze_update(ifd, val, a);
	}
    }

    process_filters_lex(&lex->select_lex, a);


}
static void
do_query_analyze(const std::string &q, LEX * lex, Analysis & analysis, bool encByDefault, const string & cur_db) {
    // iterate over the entire select statement..
    // based on st_select_lex::print in mysql-server/sql/sql_select.cc

    if (lex->sql_command == SQLCOM_CREATE_TABLE) {
        process_create_lex(lex, analysis, encByDefault, cur_db);
        return;
    }

    process_table_list(&lex->select_lex.top_join_list, analysis);

    if (lex->sql_command == SQLCOM_UPDATE) {
        process_update_lex(lex, analysis);
        return;
    }

    process_select_lex(&lex->select_lex, analysis);
}


/*
 * Analyzes how to encrypt and rewrite items in a query.
 * Results are set in analysis.
 */
static void
query_analyze(const std::string &q, LEX * lex, Analysis & analysis, bool encByDefault, const string & cur_db)
{
    // optimize the query first
    //optimize_table_list(&lex->select_lex.top_join_list, analysis);
    //optimize_select_lex(&lex->select_lex, analysis);

    do_query_analyze(q, lex, analysis, encByDefault, cur_db);
    //print(analysis.schema->tableMetaMap);
    for (auto it = analysis.tmkm.encForVal.begin(); it != analysis.tmkm.encForVal.end(); it++) {
        if (it->first == "" || it->second == "") {
            analysis.tmkm.encForVal.erase(it);
        }
    }
}


/*
 * Rewrites lex by translating and encrypting based on information in analysis.
 *
 * Fills rmeta with information about how to decrypt fields returned.
 */
static LEX *
lex_rewrite(LEX * lex, Analysis & analysis)
{
    switch (lex->sql_command) {
    case SQLCOM_CREATE_TABLE:
        return rewrite_create_lex(lex, analysis);
    case SQLCOM_INSERT:
    case SQLCOM_REPLACE:
        return rewrite_insert_lex(lex, analysis);
    case SQLCOM_DROP_TABLE: {
	LEX * new_lex = copy(lex);
	new_lex->select_lex.table_list = rewrite_table_list(lex->select_lex.table_list, analysis);
	return new_lex;
    }
    case SQLCOM_UPDATE:
        return rewrite_update_lex(lex, analysis);
    case SQLCOM_DELETE: {
	LEX * new_lex = copy(lex);
	new_lex->query_tables = rewrite_table_list(lex->query_tables, analysis);
	set_select_lex(new_lex, rewrite_select_lex(&new_lex->select_lex, analysis));
	return new_lex;
    }
    case SQLCOM_SELECT: {
        LEX * new_lex = copy(lex);
	new_lex->select_lex.top_join_list = rewrite_table_list(lex->select_lex.top_join_list, analysis);
	set_select_lex(new_lex, rewrite_select_lex(&new_lex->select_lex, analysis));
        return new_lex;
    }
    default: {
	return lex;
    }
    }
    assert_s(false, "invalid sql command");
    return NULL;
}

/*
static inline void
drop_table_update_meta(const string &q,
                       LEX *lex,
                       Analysis &a)
{
    assert(a.ps->e_conn->execute("START TRANSACTION;"));

    TABLE_LIST *tbl = lex->select_lex.table_list.first;
    for (; tbl; tbl = tbl->next_local) {
        char* dbname = tbl->db;
        char* table  = tbl->table_name;

        ostringstream s;
        s << "DELETE proxy_db.table_info, proxy_db.column_info "
          << "FROM proxy_db.table_info INNER JOIN proxy_db.column_info "
          << "WHERE proxy_db.table_info.id = proxy_db.column_info.table_id "
          << "AND   proxy_db.table_info.name = '" << table << "'"
          << "AND   proxy_db.table_info.dbname = '" << dbname << "'";

	assert(a.ps->e_conn->execute(s.str()));

        a.ps->schema->totalTables--;
        a.ps->schema->tableMetaMap.erase(table);

	assert(a.ps->e_conn->execute(q));
    }

    assert(a.ps->e_conn->execute("COMMIT"));
}
*/

static void
add_table_update_meta(const string &q,
                      LEX *lex,
                      Analysis &a)
{
    a.ps->e_conn->execute("START TRANSACTION");

    char* dbname = lex->select_lex.table_list.first->db;
    char* table  = lex->select_lex.table_list.first->table_name;
    TableMeta *tm = a.ps->schema->tableMetaMap[table];
    assert(tm != NULL);

    {
        ostringstream s;
        s << "INSERT INTO proxy_db.table_info VALUES ("
          << tm->tableNo << ", "
          << "'" << dbname << "'" << ", "
          << "'" << table << "'" << ", "
          << "'" << tm->anonTableName << "'"
          << ")";

        a.ps->e_conn->execute(s.str());
    }

    for (auto it = tm->fieldMetaMap.begin();
         it != tm->fieldMetaMap.end();
         ++it) {

        FieldMeta *fm = it->second;
        assert(it->first == fm->fname);

        ostringstream s;
        s << "INSERT INTO proxy_db.column_info VALUES ("
          << "0, " /* auto assign id */
          << tm->tableNo << ", '"
          << fm->fname << "', ";

#define __temp_write(o) \
        { \
            auto it = fm->onions.find(o); \
            if (it != fm->onions.end()) { s << "'" << it->second->onionname << "' , "; } \
            else                            { s << "NULL, ";               } \
        }
        __temp_write(oDET);
        __temp_write(oOPE);
        __temp_write(oAGG);
        __temp_write(oSWP);
#undef __temp_write

        s << "'" << fm->salt_name << "' , "
          << "1, " /* is_encrypted */
          << "1, " /* can_be_null  */
          << (fm->hasOnion(oOPE) ? "1" : "0") << ", "
          << (fm->hasOnion(oAGG) ? "1" : "0") << ", "
          << (fm->hasOnion(oSWP) ? "1" : "0") << ", "
          << (fm->has_salt       ? "1" : "0") << ", "
          << (fm->hasOnion(oOPE) ? "1" : "0") << ", " /* ope_used? */
          << (fm->hasOnion(oAGG) ? "1" : "0") << ", " /* agg_used? */
          << (fm->hasOnion(oSWP) ? "1" : "0") << ", " /* search_used? */
          << "'" << (fm->hasOnion(oOPE) ? levelnames[(int)fm->getOnionLevel(oOPE)] : "INVALID") << "' , "
	  << "'" << levelnames[(int)fm->getOnionLevel(oDET)] << "'"
          << ")";

        a.ps->e_conn->execute(s.str());
    }

    //need to update embedded schema with the new table
    a.ps->e_conn->execute(q);

    a.ps->e_conn->execute("COMMIT");
}

//TODO: potential inconsistency problem because we update state,
//but only the proxy is responsible for
static void
updateMeta(const string & q, LEX * lex, Analysis & a)
{
    switch (lex->sql_command) {
    // TODO: alter tables will need to modify the embedded DB schema
    case SQLCOM_DROP_TABLE:
        //drop_table_update_meta(q, lex, a);
        break;
    case SQLCOM_CREATE_TABLE:
        add_table_update_meta(q, lex, a);
        break;
    default:
        // no-op
        break;
    }

}

static void
dropAll(Connect * conn)
{
    for (udf_func* u: udf_list) {
        stringstream ss;
        ss << "DROP FUNCTION IF EXISTS " << convert_lex_str(u->name) << ";";
        assert_s(conn->execute(ss.str()), ss.str());
    }
}

static void
createAll(Connect * conn)
{
    for (udf_func* u: udf_list) {
        stringstream ss;
        ss << "CREATE ";
        if (u->type == UDFTYPE_AGGREGATE) ss << "AGGREGATE ";
        ss << "FUNCTION " << u->name.str << " RETURNS ";
        switch (u->returns) {
            case INT_RESULT:    ss << "INTEGER"; break;
            case STRING_RESULT: ss << "STRING";  break;
            default:            thrower() << "unknown return " << u->returns;
        }
        ss << " SONAME 'edb.so';";
        assert_s(conn->execute(ss.str()), ss.str());
    }
}

static void
loadUDFs(Connect * conn) {
    //need a database for the UDFs
    assert_s(conn->execute("DROP DATABASE IF EXISTS cryptdb_udf"), "cannot drop db for udfs even with 'if exists'");
    assert_s(conn->execute("CREATE DATABASE cryptdb_udf;"), "cannot create db for udfs");
    assert_s(conn->execute("USE cryptdb_udf;"), "cannot use db");
    dropAll(conn);
    createAll(conn);
    LOG(cdb_v) << "Loaded CryptDB's UDFs.";
}


Rewriter::Rewriter(ConnectionInfo ci,
                   const std::string &embed_dir,
                   bool multi,
		   bool encByDefault)
{

    init_mysql(embed_dir);

    ps.ci = ci;
    ps.encByDefault = encByDefault;

    urandom u;
    ps.masterKey = getKey(u.rand_string(AES_KEY_BYTES));

    if (multi) {
		ps.encByDefault = false;
    }

    ps.e_conn = Connect::getEmbedded(embed_dir);

    ps.conn = new Connect(ci.server, ci.user, ci.passwd, ci.port);

    ps.schema = new SchemaInfo();
    ps.totalTables = 0;
    initSchema(ps);

    loadUDFs(ps.conn);

    if (multi) {
        ps.mp = new MultiPrinc(ps.conn);
    } else {
        ps.mp = NULL;
    }
}

ProxyState::~ProxyState()
{
    if (mp) {
        delete mp;
        mp = NULL;
    }
    if (conn) {
        delete conn;
        conn = NULL;
    }
    if (e_conn) {
	delete e_conn;
	e_conn = NULL;
    }
}
Rewriter::~Rewriter()
{
}

void
Rewriter::setMasterKey(const string &mkey)
{
    ps.masterKey = getKey(mkey);
}

static list<string>
processAnnotation(Annotation annot, Analysis &a)
{
    MultiPrinc * mp = a.ps->mp;
    SchemaInfo * schema = a.ps->schema;

    if (mp && annot.type != ENCFOR) {
        bool encryptField;
        return mp->processAnnotation(annot, encryptField, schema);
    }

    //TODO: use EncLayer CreateField information
    assert_s(annot.type == SINGLE_ENC || annot.type == ENCFOR,
	     "parser is in single principal mode, but annotations are for multiple principals");
    assert_s(annot.getPrimitive() != "",
	     "enc annotation has no primitive");
    LOG(cdb_v) << "table is " << annot.getPrimitiveTableName() << "; field is " << annot.getPrimitiveFieldName();

    FieldMeta * fm = schema->getFieldMeta(annot.getPrimitiveTableName(), annot.getPrimitiveFieldName());

    if (mp) {
        init_onions_mp(a.ps->masterKey, fm, fm->sql_field, fm->index);
    } else {
        init_onions(a.ps->masterKey, fm, fm->sql_field, fm->index);
    }

    if (mp) {
        bool encryptField;
        return mp->processAnnotation(annot, encryptField, schema);
    }

    list<string> query_list;
    string onionname = "";

    for (auto pr : fm->encdesc.olm) {
        onion o = pr.first;
        onionname = fm->onions[o]->onionname;
        Create_field * cf = fm->onions[o]->layers.back()->newCreateField(onionname);

        stringstream query;
        query << "ALTER TABLE " << fm->tm->anonTableName;

        switch (o) {
        case oDET:
            LOG(cdb_v) << fm->fname << " (" << fm->index << ") gets DET onion";
            query << " CHANGE " << fm->fname << " " <<  *cf << ";";
            break;
        case oOPE:
            LOG(cdb_v) << fm->fname << " (" << fm->index << ") gets OPE onion";
            query << " ADD " << *cf << " AFTER " << fm->onions[oDET]->onionname << ";";
            break;
        case oAGG:
            LOG(cdb_v) << fm->fname << " (" << fm->index << ") gets AGG onion";
            query << " ADD " << *cf <<  " AFTER " << fm->onions[oOPE]->onionname << ";";
            break;
        case oSWP:
            LOG(cdb_v) << fm->fname << " (" << fm->index << ") gets SWP onion";
            query << " ADD " << *cf << " AFTER " << fm->onions[oOPE]->onionname << ";";
            break;
        default:
            assert_s(false, "unknown onion type");
        }

        query_list.push_back(query.str());
    }

    query_list.push_back("ALTER TABLE " + fm->tm->anonTableName  +
                         " ADD " + fm->salt_name + " " + TN_SALT +
                         " AFTER " + onionname + ";");

    return query_list;
}

static void
mp_init(Analysis &a) {
    //start new temp mkm
    a.tmkm.encForVal.clear();
    a.tmkm.encForReturned.clear();
    a.tmkm.processingQuery = false;
    a.tmkm.returnBitMap.clear();
}

static list<string>
rewrite_helper(const string & q, Analysis & analysis,
	       query_parse & p, const string & cur_db) {
    LOG(cdb_v) << "q " << q;
    list<string> queries;

    //initialize multi-principal
    mp_init(analysis);

    if (p.annot) {
        return processAnnotation(*p.annot, analysis);
    }

    LEX *lex = p.lex();

    //login/logout command; nothing needs to be passed on
    if ((lex->sql_command == SQLCOM_DELETE || lex->sql_command == SQLCOM_INSERT)
        && analysis.ps->mp && analysis.ps->mp->checkPsswd(lex)){
	LOG(cdb_v) << "login/logout " << *lex;
        return queries;
    }
    LOG(cdb_v) << "pre-analyze " << *lex;

    //TODO: is db neededs as param in all these funcs?
    //analyze query
    query_analyze(q, lex, analysis, analysis.ps->encByDefault, cur_db);

    //update metadata about onions if it's not delete
    if (lex->sql_command != SQLCOM_DROP_TABLE) {
        updateMeta(q, lex, analysis);
    }
    //TODO:these two invokations of updateMeta are confusing:
    //one is for adjust onions, and other for dropping table

    //rewrite query
    LEX * new_lex = lex_rewrite(lex, analysis);
    if (new_lex->sql_command == SQLCOM_DROP_TABLE) {
        updateMeta(q, new_lex, analysis);
    }
    stringstream ss;
    ss << *new_lex;
    LOG(cdb_v) << "FINAL QUERY: " << *new_lex << endl;
    queries.push_back(ss.str());
    return queries;
}

static bool
noRewrite(LEX * lex) {
    switch (lex->sql_command) {
    case SQLCOM_SHOW_DATABASES:
    case SQLCOM_SET_OPTION:
    case SQLCOM_BEGIN:
    case SQLCOM_COMMIT:
    case SQLCOM_SHOW_TABLES:
	return true;
    case SQLCOM_SELECT: {

    }
    default:
	return false;
    }

    return false;
}

// TODO: we don't need to pass analysis, enough to pass returnmeta
QueryRewrite
Rewriter::rewrite(const string & q, string *cur_db)
{

    assert(0 == mysql_thread_init());
    //assert(0 == create_embedded_thd(0));

    query_parse p(*cur_db, q);
    QueryRewrite res;

    //optimization: do not process queries that we will not rewrite
    if (noRewrite(p.lex())) {
	res.wasRew = false;
	res.queries.push_back(q);
	return res;
    }

    //for as long as there are onion adjustments
    while (true) {
	Analysis analysis = Analysis(&ps);
	try {
	    res.queries = rewrite_helper(q, analysis, p, *cur_db);
	} catch (OnionAdjustExcept e) {
	    LOG(cdb_v) << "caught onion adjustment";
	    adjustOnion(e.o, e.fm, e.tolevel, e.itf, analysis, *cur_db);
	    continue;
	}
	res.wasRew = true;
	res.rmeta = analysis.rmeta;
	res.rmeta->tmkm = analysis.tmkm;
	return res;
    }
}

//TODO: replace stringify with <<
string ReturnField::stringify() {
    stringstream res;

    res << " is_salt: " << is_salt << " filed_called " << field_called;
    res <<" fm  " << olk.key << " onion " << olk.o;
    res << " pos_salt " << pos_salt;

    return res.str();
}
string ReturnMeta::stringify() {
    stringstream res;
    res << "rmeta contains " << rfmeta.size() << " elements: \n";
    for (auto i : rfmeta) {
	res << i.first << " " << i.second.stringify() << "\n";
    }
    return res.str();
}
static void
mp_init_decrypt(MultiPrinc * mp, Analysis & a) {
    if (!mp) {return;}

    a.tmkm.processingQuery = false;
    LOG(cdb_v) << a.rmeta->stringify() << "\n";
    for (auto i = a.rmeta->rfmeta.begin(); i != a.rmeta->rfmeta.end(); i++) {
        if (!i->second.is_salt) {
            a.tmkm.encForReturned[fullName(i->second.olk.key->fname, i->second.olk.key->tm->anonTableName)] = i->first;
        }
    }
}

ResType
Rewriter::decryptResults(ResType & dbres,
			 ReturnMeta * rmeta) {

    Analysis a = Analysis(&ps);
    a.rmeta = rmeta;
    a.tmkm = rmeta->tmkm;

    mp_init_decrypt(ps.mp, a);
    unsigned int rows = dbres.rows.size();
    LOG(cdb_v) << "rows in result " << rows << "\n";
    unsigned int cols = dbres.names.size();

    ResType res = ResType();

    unsigned int index = 0;

    // un-anonymize the names
    for (auto it = dbres.names.begin();
	 it != dbres.names.end(); it++) {
        ReturnField rf = rmeta->rfmeta[index];
        if (!rf.is_salt) {
	    //need to return this field
            res.names.push_back(rf.field_called);
	    // switch types to original ones : TODO

        }
        index++;
    }

    unsigned int real_cols = res.names.size();


    //allocate space in results for decrypted rows
    res.rows = vector<vector<Item*> >(rows);
    for (unsigned int i = 0; i < rows; i++) {
        res.rows[i] = vector<Item*>(real_cols);
    }

    // decrypt rows
    unsigned int col_index = 0;
    for (unsigned int c = 0; c < cols; c++) {
        ReturnField rf = rmeta->rfmeta[c];
        FieldMeta * fm = rf.olk.key;

        if (!rf.is_salt) {
            for (unsigned int r = 0; r < rows; r++) {
                if (!fm || !fm->isEncrypted()) {
                    res.rows[r][col_index] = dbres.rows[r][c];
                } else {
                    uint64_t salt = 0;
                    if (rf.pos_salt>=0) {
                        Item * salt_item = dbres.rows[r][rf.pos_salt];
                        assert_s(!salt_item->null_value, "salt item is null");
                        salt = ((Item_int *)dbres.rows[r][rf.pos_salt])->value;
                    }
		    res.rows[r][col_index] = decrypt_item(fm, rf.olk.o, dbres.rows[r][c], salt, a, res.rows[r]);
                }
            }
            col_index++;
        }
    }


    return res;
}


void
printRes(const ResType & r) {

    //if (!cryptdb_logger::enabled(log_group::log_edb_v))
    //return;

    std::stringstream ssn;
    for (unsigned int i = 0; i < r.names.size(); i++) {
        char buf[400];
        snprintf(buf, sizeof(buf), "%-25s", r.names[i].c_str());
        ssn << buf;
    }
    std::cerr << ssn.str() << std::endl;
    //LOG(edb_v) << ssn.str();

    /* next, print out the rows */
    for (unsigned int i = 0; i < r.rows.size(); i++) {
	stringstream ss;
        for (unsigned int j = 0; j < r.rows[i].size(); j++) {
            char buf[400];
            std::stringstream sstr;
            sstr << *r.rows[i][j];
            snprintf(buf, sizeof(buf), "%-25s", sstr.str().c_str());
            ss << buf;
        }
        std::cerr << ss.str() << std::endl;
        //LOG(edb_v) << ss.str();
    }
}
