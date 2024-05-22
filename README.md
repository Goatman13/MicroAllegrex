# MicroAllegrex
Allegrex Plugin for IDA Hexrays Mips Decompiler. Plugin helps with basic decompilation of Allegrex specific opcodes.

## Supported opcodes:
* bitrev
* mfic
* min
* max
* wsbw

## Usage
* Copy into ida plugins directory.
* Push F5 if previously recompiled code isn't fixed.
* Tested on IDA 7.5 with python 3.

## Issues
* Not implemented mtic.
* Opcodes in delay slot are not supported.

## Examples
Before:

![before1](https://github.com/Goatman13/MicroAllegrex/assets/101417270/e8bd0fe4-08a1-41c2-b376-09eabc0375fe)

After:

![after1](https://github.com/Goatman13/MicroAllegrex/assets/101417270/91ecc530-016a-4d31-843e-d6bd309c9e2c)


Before:

![before2](https://github.com/Goatman13/MicroAllegrex/assets/101417270/87a2ba32-353a-462c-b4b0-979bc0a3ae6f)

After:


![after2](https://github.com/Goatman13/MicroAllegrex/assets/101417270/ada4a359-bd85-45a1-bfbf-76164947665e)

Before:

![before3](https://github.com/Goatman13/MicroAllegrex/assets/101417270/e22bdf2d-dc48-4ebc-959d-be3831353a46)

After:

![after3](https://github.com/Goatman13/MicroAllegrex/assets/101417270/c3b18cfa-de7f-4319-baf4-5023dc439a3a)


