#include <cstdlib>
#include <cstdio>
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
#include <functional>
#include <cctype>
#include <locale>

#include <main/Connect.hh>

#include <unistd.h>

#include <main/cdb_rewrite.hh>

#include <readline/readline.h>
#include <readline/history.h>

#include <parser/embedmysql.hh>
#include <parser/stringify.hh>

#include <crypto/ecjoin.hh>

#include <util/errstream.hh>
#include <util/cryptdb_log.hh>

using namespace std;

// if true, uses MultiPrinc mode
static bool Multi = false;

static bool encByDefault = true;


static inline string user_homedir() {
    return getenv("HOME");
}

static inline string user_histfile() {
    return user_homedir() + "/.cryptdb-history";
}

static void __write_history() {
    write_history(user_histfile().c_str());
}

static inline std::string &ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

static inline std::string &rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
  return s;
}

static inline std::string &trim(std::string &s) {
  return ltrim(rtrim(s));
}

static const std::string BOLD_BEGIN = "\033[1m";
static const std::string RED_BEGIN = "\033[1;31m";
static const std::string GREEN_BEGIN = "\033[1;92m";
static const std::string COLOR_END = "\033[0m";


static string prettyq(string s) {
  stringstream res;

  for (uint i = 0; i < s.length(); i++) {
    char c = s[i];
    if (isalnum(c) || (c == ' ') || (c == ')') || (c == '(')) {
      res <<  c;
    } else {
      res << hex << (int)c;
    }
  }

  return res.str();
}


/** returns true if should stop, to keep looping */
static bool handle_line(Connect& conn, Rewriter& r, const string& q)
{
  if (q == "\\q") {
    cerr << "Goodbye!\n";
    return false;
  }

  add_history(q.c_str());

  // handle meta inputs
  if (q.find(":load") == 0) {
    string filename = q.substr(6);
    trim(filename);
    cerr << RED_BEGIN << "Loading commands from file: " << filename << COLOR_END << endl;
    ifstream f(filename.c_str());
    if (!f.is_open()) {
      cerr << "ERROR: cannot open file: " << filename << endl;
    }
    while (f.good()) {
      string line;
      getline(f, line);
      if (line.empty())
        continue;
      cerr << GREEN_BEGIN << line << COLOR_END << endl;
      if (!handle_line(conn, r, line)) {
        f.close();
        return false;
      }
    }
    f.close();
    return true;
  }

  DBResult * dbres;
  QueryRewrite qr;

  try {
    string curdb("cryptdbtest");
    qr = r.rewrite(q, &curdb);
    //only last query should return anything
    if (qr.queries.size() == 0) {
      return true;
    }
    for (auto new_q = qr.queries.begin(); new_q != qr.queries.end(); new_q++) {
      cerr << endl
           << RED_BEGIN << "ENCRYPTED QUERY:" << COLOR_END << endl
           << *new_q << endl;
      assert(conn.execute(*new_q, dbres));
    }
    if (!dbres) {
      return true;
    }

    ResType res = dbres->unpack();

    if (!res.ok) {
      return true;
    }
    cerr << endl << RED_BEGIN << "ENCRYPTED RESULTS FROM DB:" << COLOR_END << endl;
    printRes(res);
    cerr << endl;
    ResType dec_res = r.decryptResults(res, qr.rmeta);

    cerr << endl << RED_BEGIN << "DECRYPTED RESULTS:" << COLOR_END << endl;
    printRes(dec_res);

  } catch (std::runtime_error &e) {
    cout << "Unexpected Error: " << e.what() << " in query " << q << endl;
  } catch (CryptDBError &e) {
    cout << "Internal Error: " << e.msg << " in query " << q << endl;
  }

  return true;
}

int
main(int ac, char **av)
{
    if (ac != 2) {
        cerr << "Usage: " << av[0] << " embed-db " << endl;
        exit(1);
    }

    using_history();
    read_history(user_histfile().c_str());
    atexit(__write_history);


    ConnectionInfo ci("localhost", "root", "letmein");

    Rewriter r(ci, av[1], Multi, encByDefault);
    //TODO: conn creation has to occur after rewriter creation
    //because rewriter inits mysql library; fix this
    Connect conn("localhost", "root", "letmein", "cryptdbtest");

    r.setMasterKey("2392834");

    string prompt = BOLD_BEGIN + "CryptDB=#" + COLOR_END + " ";

    for (;;) {
        char *input = readline(prompt.c_str());
        if (!input) break;
        string q(input);
        if (q.empty()) continue;
        if (!handle_line(conn, r, q))
          break;
    }
}
