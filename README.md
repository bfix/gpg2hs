gpg2hs
======

Convert GnuPG private keys to Tor hidden service keys (and vice versa)
(c) 2014 Bernd Fix   >Y<

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Introduction
------------

There are two application bundled in this project:

* `gpg2hs` converts GnuPG private keys into Tor hidden services parameter
  files `hostname` (to hold the onion address of the hidden service)
  and `private_key` (the RSA key used by the hidden service)

* `hs2gpg` can convert Tor hidden service paramter files (see above) into
  a single armored GnuPG private key file. Such a file can then be imported
  into a notm GnuPG keyring.

Usage
-----

### Create hidden service parameter files from a GnuPG private key

The following call let users create Tor hidden service parameter files from
a single GnuPG private key:

`gpg2hs -c -k <key identifier> [-s <secring.gpg>] [-t <outdir>]`

#### Options

**`-c`** Create mode: Generate Tor hidden service parameter files

**`-k <key identifier>`** Must match a single private key from the keyring

**`-s <secring.gpg>`** Specify the private keyring to be used. The default
	keyring is the standard GnuPG keyring located at `~/.gnupg/secring.gpg`
     
**`-t <outdir>`** Specify the output directory where the parameter files will
	be generated. The output directory defaults to the current directory.   

### Verify onion address with GnuPG public key

The following call allows users to verify that a certain onion address
belongs to a (known) GnuPG key: 

`gpg2hs -v -k <key identifier> [-p <pubring.gpg>]`

#### Options

**`-v`** Verification mode: Output onion address(es) only

**`-k <key identifier>`** All public keys matching `key identifier` from a
	public keyring are processed.
     
**`-p <pubring.gpg>`** Specify the public keyring to be used. The default
	keyring is the standard GnuPG keyring located at `~/.gnupg/pubring.gpg` 

### Create GnuPG ASCII-armored private key file from Tor hidden service
    parameter files

`hs2gpg -i <private_key> -o <key.asc>`

#### Options

**`-i <private_key>`** Tor hidden service key file to be converted. Defaults
	to the file `private key` in the current directory.

**`-o <key.asc>`** Geerated GnuPG ASCII-armored private key file. The file is
	unencrypted and ready for import into GnuPG. It defaults to the file
	`key.asc` int the current directory.
