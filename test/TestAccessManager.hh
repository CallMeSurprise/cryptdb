#pragma once

/*
 * TestAccessManager.h
 *
 * Created on: July 21, 2011
 *  Author: cat_red
 */

//#include <edb/AccessManager.hh>
#include <edb/AM_client.hh>
#include <test/test_utils.hh>


class TestAccessManager {
 public:
  TestAccessManager();
  virtual
    ~TestAccessManager();

  static void run(const TestConfig &tc, int argc, char ** argv);
};
