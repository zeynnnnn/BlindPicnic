# Picnic Digital Signature Scheme with Key-Blinding

This is the Picnic with key blinding developed on top of the https://github.com/microsoft/Picnic repository as a part of my Master Thesis.  

The library builds a static library.  The public API surface is defined in [picnic.h] along with the non key-blinding API of https://github.com/Microsoft/Picnic/.

## Linux Build Instructions

Tested on Ubuntu Linux, and the Windows Subsystem for Linux on Windows 10 (build 1709).

1. `make`  
This will build the project.  `make debug` will build with symbols.

2. `./example`  
Runs an example program that exercises the keygen, sign, verify and
serialization APIs.  See [example.c](https://github.com/Microsoft/Picnic/blob/master/example.c).


