Installation Process:

This project has been built and tested on Mac and Linux (Mint and Debian), although is easiest on Linux. This readme focuses on the Linux installation process

Before starting, the following miscellaneous tools should be installed:
libtool
gcc-13
g++-13
cmake
openssl-dev

Ensure that C versions 13 are used throughout the building process!

This project has two main dependencies:
1) libOTe {https://github.com/osu-crypto/libOTe}, for Oblivious Transfers
2) emp-sh2pc {https://github.com/emp-toolkit/emp-sh2pc}, for the Garbled Circuit

libOTe can present some difficulties with installation and the MACORO tests have some bugs in them - I used the following command for the final build step:
CC=gcc-13 CXX=g++-13 python3 build.py --all --sodium --relic --boost -DMACORO_TESTS=OFF -DCMAKE_CXX_STANDARD=20

API:
Server 1 is run with the following parameters:
1) The number of records to generate in the dataset n
2) The number of attributes in the dataset m
3) The bitlength of each attribute L
4) The ET protocol to be used. 0 = Intersect, 1 = CouteauFull, 2 = Hybrid (Couteau size-reduction then Intersect on the reduced strings)
5) "v" for verbose or nothing for no verbose

Server 2 is run with no parameters.
Client is run with no parameters.

Example run of the program:
1) Run server 1: ./intersect_server1 8 4 4 0 v   -> 8 records, 4x4 dataset, using protocol Intersect with verbose
2) Run server 2: ./intersect_server2
3) Run client: ./intersect_client
4) Client will ask whether to submit data or make a query
5) Submit data: write the record you want to add of size m * L, e.g. 0010101101011111
6) Make query: Client will ask which attributes you wish to query over (which generates the q vector), e.g. 1,3
7) Make query pt2: Client will ask for your query (which generates the t vector), e.g. 00100101
8) Make query pt3: Client tells you if you're vulnerable, e.g. if t = 1 for this example, we'd get 'not vulnerable' since the query matches the record we added

Multiple clients can connect simultaneously and can disconnect whenever.
