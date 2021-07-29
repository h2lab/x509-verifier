# x509-verif project

## Copyright and license
Copyright (C) 2021

This software is licensed under a dual BSD and GPL v2 license.
See [LICENSE](LICENSE) file at the root folder of the project.

## Authors

  * Arnaud EBALARD (<mailto:arnaud.ebalard@ssi.gouv.fr>)
  * Ryad BENADJILA (<mailto:ryad.benadjila@ssi.gouv.fr>)

## Description

This software implements a X.509 certificate verifier based on the parsing
capabilities of x509-parser project and on the signature verification
capabilities provided by libecc project.

## Building

The main [Makefile](Makefile) is in the root directory, and compiling is
as simple as executing:

<pre>
	$ make
</pre>

This will compile different elements in the [build](build/) directory:

  * various object files
  * the x509-parser-verif binary
