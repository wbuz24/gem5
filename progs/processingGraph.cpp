// Will Buziak
// Process stats file from command line and output jgraph
#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
using namespace std;

int main(int argc, char** argv)
{
  string fname, line, s;
  ifstream file;
  istringstream ss;
  vector <string> sv;
  int i;

  if (argc != 2) { fprintf(stderr, "USAGE:\n./processGraph /path/To/stats.txt\n"); exit(1); }

  // grab filename
  fname = argv[1];

  printf("Processing %s\n", fname.c_str());

  // open file
  file.open(fname);
  if (!file) { fprintf(stderr, "%s failed to open\n", fname.c_str()); exit(1); }
  
  // Process each line
  while (getline(file, line)) {
    sv.clear(); // clear vector/streams and insert new line
    ss.clear();
    ss.str(line);

    while (ss >> s) sv.push_back(s); // process string stream into vector

    // print each line
    for (i = 0; i < sv.size(); i++) { printf("%s ", sv[i].c_str()); }
    printf("\n");
  }

  return 0;
}
