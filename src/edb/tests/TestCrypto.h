/*
 * TestCrypto.h
 *
 *  Created on: Jul 15, 2011
 *      Author: cat_red
 */

#include "OPE.h"
#include "HGD.h"

#ifndef TESTCRYPTO_H_
#define TESTCRYPTO_H_

class TestCrypto {
 public:
    TestCrypto();
    virtual
    ~TestCrypto();

    static void run(int argc, char ** argv);
};

#endif /* TESTCRYPTO_H_ */
