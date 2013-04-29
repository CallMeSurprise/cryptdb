#pragma once

#include <string>
#include <map>
#include <list>
#include <iostream>


typedef enum onion {
    oDET,
    oOPE,
    oAGG,
    oELG,
    oSWP,
    oPLAIN, 
    oINVALID,
} onion;

//Sec levels ordered such that
// if a is less secure than b.
// a appears before b
// (note, this is not "iff")
#define SECLEVELS(m)    \
    m(INVALID)          \
    m(PLAINVAL)         \
    m(ELG)              \
    m(OPEJOIN)     	\
    m(OPE)		\
    m(DETJOIN)          \
    m(DET)              \
    m(SEARCH)           \
    m(HOM)              \
    m(RND) 		\
    m(SECLEVEL_LAST)

typedef enum class SECLEVEL {
#define __temp_m(n) n,
SECLEVELS(__temp_m)
#undef __temp_m
} SECLEVEL;

//TODO: what is seclevel_last needed for?

const std::string levelnames[] = {
#define __temp_m(n) #n,
SECLEVELS(__temp_m)
#undef __temp_m
};

inline SECLEVEL string_to_sec_level(const std::string &s)
{
#define __temp_m(n) if (s == #n) return SECLEVEL::n;
SECLEVELS(__temp_m)
#undef __temp_m
    // TODO: possibly raise an exception
    return SECLEVEL::INVALID;
}

bool needsSalt(SECLEVEL l);

//Onion layouts - initial structure of onions
typedef std::map<onion, std::list<SECLEVEL> > onionlayout;

static onionlayout PLAIN_ONION_LAYOUT = {
    {oPLAIN, std::list<SECLEVEL>({SECLEVEL::PLAINVAL})}
};

static onionlayout NUM_ONION_LAYOUT = {
    {oDET, std::list<SECLEVEL>({SECLEVEL::DETJOIN, SECLEVEL::DET, SECLEVEL::RND})},
    {oOPE, std::list<SECLEVEL>({SECLEVEL::OPE, SECLEVEL::RND})},
    {oAGG, std::list<SECLEVEL>({SECLEVEL::HOM})},
    {oELG, std::list<SECLEVEL>({SECLEVEL::ELG})}
};

static onionlayout MP_NUM_ONION_LAYOUT = {
    {oDET, std::list<SECLEVEL>({SECLEVEL::DETJOIN, SECLEVEL::DET, SECLEVEL::RND})},
    {oOPE, std::list<SECLEVEL>({SECLEVEL::OPE, SECLEVEL::RND})}
};
    
static onionlayout STR_ONION_LAYOUT = {
    {oDET, std::list<SECLEVEL>({SECLEVEL::DETJOIN, SECLEVEL::DET, SECLEVEL::RND})},
    {oOPE, std::list<SECLEVEL>({SECLEVEL::OPE, SECLEVEL::RND})},
    {oSWP, std::list<SECLEVEL>({SECLEVEL::SEARCH})}
};

typedef std::map<onion, SECLEVEL>  OnionLevelMap;

/**
 * Use to keep track of a field's encryption onions.
 */
class EncDesc {
public:
    EncDesc() {}
    EncDesc(OnionLevelMap input) : olm(input) {}
    EncDesc(const EncDesc & ed) : olm(ed.olm) {}
    /**
     * Returns true if something was changed, false otherwise.
     */
    bool restrict(onion o, SECLEVEL maxl);
    EncDesc intersect(EncDesc & ed);
    void clear() {olm.clear();};
    
    OnionLevelMap olm;
};

std::ostream& operator<<(std::ostream &out, const EncDesc & ed);

const EncDesc FULL_EncDesc = {
        {
            {oDET, SECLEVEL::DET},
            {oOPE, SECLEVEL::OPE},
            {oAGG, SECLEVEL::HOM},
            {oSWP, SECLEVEL::SEARCH},
            {oELG, SECLEVEL::ELG},
        }
};

//initial onion configurations 
const EncDesc NUM_initial_levels = {
        {
            {oDET, SECLEVEL::DET},
            {oOPE, SECLEVEL::OPE},
            {oAGG, SECLEVEL::HOM},
            {oELG, SECLEVEL::ELG},
        }
};

const EncDesc STR_initial_levels = {
        {
            {oDET, SECLEVEL::DET},
            {oOPE, SECLEVEL::OPE},
            {oSWP, SECLEVEL::SEARCH},
        }
};
