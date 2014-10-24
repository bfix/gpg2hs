gpg2hs
======

Convert GnuPG private keys to Tor Hidden Service keys (and vice versa)

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

* `gpg2hs` converts GnuPG private subkeys into Tor Hidden Service parameter
  files `hostname` (to hold the onion address of the hidden service)
  and `private_key` (the RSA key used by the hidden service)

* `hs2gpg` can convert Tor hidden service parameter files (see above) into
  a single armored GnuPG private key file with a matching subkey. Such a file
  can then be imported into a GnuPG keyring with `gpg --import <key.asc>`.

*CAVEAT*: Tor hidden service are currently only able to work with 1024-bit
RSA keys. Make sure that the subkeys you have defined in GnuPG for Hidden
Serices are RSA keys of the same size. It is recommended (but not mandatory)
to use RSA-1024 subkeys without usage flags, so that these subkeys will never
be used by GnuPG itself for other purposes. See `Appendix A` for an example
on how to create matching subkeys. 

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

### Create GnuPG ASCII-armored private key file from Tor hidden service parameter files

`hs2gpg -i <private_key> -o <key.asc>`

#### Options

**`-i <private_key>`** Tor hidden service key file to be converted. Defaults
	to the file `private key` in the current directory.

**`-o <key.asc>`** Generated GnuPG ASCII-armored private key file. The file is
	unencrypted and ready for import into GnuPG. It defaults to the file
	`key.asc` in the current directory.

Appendix A: Create suitable subkeys
-----------------------------------

Let's assume we have the following GnuPG key:

    pub   2048R/BE16C48E 2014-10-24
          Key fingerprint = 071C 5809 32BB 1E61 135F  A902 DD25 DB98 BE16 C48E
    uid                  Allium Cepa <cepa@mail.example>
    sub   2048R/A140F631 2014-10-24

We can now create a suitable subkey:

`$ gpg --expert --edit-key BE16C48E`

    gpg (GnuPG) 1.4.18; Copyright (C) 2014 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    
    Secret key is available.
    
    pub  2048R/BE16C48E  created: 2014-10-24  expires: never       usage: SC  
                         trust: ultimate      validity: ultimate
    sub  2048R/A140F631  created: 2014-10-24  expires: never       usage: E   
    [ultimate] (1). Allium Cepa <cepa@mail.example>
    
    gpg> addkey
    Key is protected.
    
    You need a passphrase to unlock the secret key for
    user: "Allium Cepa <cepa@mail.example>"
    2048-bit RSA key, ID BE16C48E, created 2014-10-24
    
    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
    Your selection? 8
    
    Possible actions for a RSA key: Sign Encrypt Authenticate 
    Current allowed actions: Sign Encrypt 
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? s
    
    Possible actions for a RSA key: Sign Encrypt Authenticate 
    Current allowed actions: Encrypt 
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? e
    
    Possible actions for a RSA key: Sign Encrypt Authenticate 
    Current allowed actions: 
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? q
    RSA keys may be between 1024 and 4096 bits long.
    What keysize do you want? (2048) 1024
    Requested keysize is 1024 bits
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0) 
    Key does not expire at all
    Is this correct? (y/N) y
    Really create? (y/N) y
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    +++++
    +++++
    
    pub  2048R/BE16C48E  created: 2014-10-24  expires: never       usage: SC  
                         trust: ultimate      validity: ultimate
    sub  2048R/A140F631  created: 2014-10-24  expires: never       usage: E   
    sub  1024R/AA42D3D8  created: 2014-10-24  expires: never       usage:     
    [ultimate] (1). Allium Cepa <cepa@mail.example>
    
    gpg> save

The newly created key `AA42D3D8` is suitable for hidden services.