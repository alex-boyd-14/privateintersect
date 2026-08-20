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
1) The number of records to generate in the dataset
2) The number of attributes in the dataset
3) The bitlength of each attribute
4) The ET protocol to be used. 0 = Intersect, 1 = CouteauFull, 2 = Hybrid (Couteau size-reduction then Intersect on the reduced strings)
5) "v" for verbose or nothing for no verbose

Server 2 is run with no parameters.

