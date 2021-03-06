#pragma once

/*
 * MultiPrincipal.h
 *
 * Performs the high level multi-principal work: parsing and interaction with
 * key access.
 */

#include <main/AccessManager.hh>
#include <main/Translator.hh>
#include <main/schema.hh>
#include <parser/Annotation.hh>

class MultiPrinc {
 public:
    MultiPrinc(Connect * conn);

    virtual
    ~MultiPrinc();

    /***  CREATE TABLES tasks ***/

    /*
     *
     * processes access link
     * sets wordsIt to next field to process in Create
     * updates encforMap and accMan
     * sets encryptfield
     */
    /*void processAnnotation(std::list<std::string>::iterator & wordsIt,
                           std::list<std::string> & words, std::string tablename,
                           std::string currentField,
                           bool & encryptfield, std::map<std::string,
                           TableMetadata *> & tm);*/
    std::list<std::string> processAnnotation(Annotation &annot, bool &encryptField,
                                        SchemaInfo * schema);

    int commitAnnotations();

    /*** LOGIN tasks ***/

    bool isActiveUsers(const std::string &query);

    bool checkPsswd(LEX *lex);
    //bool checkPsswd(command comm, std::list<std::string> & words);

  
    bool hasEncFor(std::string field);

    // fills tmkm.encForReturned and decides if the next field was added by us
    // and should not be returned to the user
    void processReturnedField(unsigned int index, bool isNextSalt, std::string fullname, onion o,
                              TMKM &tmkm,
                              bool & ignore);

    bool checkPredicate(const AccessRelation & accRel, std::map<std::string, std::string> & vals);

    /*** INSERT tasks ***/
    
    void insertLex(LEX *lex, SchemaInfo * schema, TMKM &tmkm);
    //wordsIt points to the first value
    void insertRelations(const std::list<std::pair<std::string, bool> > & values, std::string table,
                         std::list<std::string> fields,
                         TMKM &tmkm);

    /*** OTHER ***/

    bool isPrincipal(std::string fullname);

    // -- Determines which key to use for a field
    // -- They return null if the set of active users cannot decrypt current
    // field
    // -- the key is to be used for a query
    std::string get_key(std::string fieldName, TMKM & tmkm);

    // -- Determines which key to use for a field
    // -- They return null if the set of active users cannot decrypt current
    // field
    // -- the key is to be used for a result set
    std::string get_key(std::string fieldName, TMKM & tmkm,
                   const std::vector<Item *> &res);

 private:
    Connect * conn;
    MultiKeyMeta mkm;
    KeyAccess * accMan;
    MultiPrinc * mp;

    //utility function for checking that schema is okay, and setting tm to sensitive
    bool setSensitive(SchemaInfo *schema, std::string table_name, std::string field);
};
