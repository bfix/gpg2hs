/*
 * `hs2gpg` converts Tor Hidden Service keys into GnuPG subkeys.
 *
 * (c) 2014 Bernd Fix   >Y<
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

///////////////////////////////////////////////////////////////////////
// Import external declarations.

import (
	"bufio"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

///////////////////////////////////////////////////////////////////////
// package-global variables

var (
	keyfile   string
	gpgkey   string
)

///////////////////////////////////////////////////////////////////////
// Main functions

/*
 * Read RSA-1024 key from file
 * @param fName string - name of file to be read
 * @return *rsa.PrivateKey - key read from file	
 */
func readHiddenServiceKey(fName string) *rsa.PrivateKey {
	fp, err := os.Open(fName)
	if err != nil {
		log.Fatal("[1]" + err.Error())
	}
	defer fp.Close()
	rdr := bufio.NewReader(fp)
	buf := ""
	for state := 1; state != 0; {
		data, _, err := rdr.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("[2]" + err.Error())
		}
		line := string(data)
		switch state {
		case 1:
			if line == "-----BEGIN RSA PRIVATE KEY-----" {
				state = 2
			}
		case 2:
			if line == "-----END RSA PRIVATE KEY-----" {
				state = 0
			} else {
				buf += line
			}
		}
	}
	derKey, err := base64.StdEncoding.DecodeString(buf)
	if err != nil {
		log.Fatal("[3]" + err.Error())
	}
	prvKey, err := x509.ParsePKCS1PrivateKey(derKey)
	return prvKey
}

//---------------------------------------------------------------------
/*
 * Read GnuPG entity from file
 * @param fName string - name of file to be read
 * @return *rsa.PrivateKey - key read from file	
 */
func readGpgKey(fName string) *openpgp.Entity {
	fp, err := os.Open(fName)
	if err != nil {
		log.Fatal("[4]" + err.Error())
	}
	defer fp.Close()
	ents, err := openpgp.ReadArmoredKeyRing(fp)
	if err != nil {
		log.Fatal("[5]" + err.Error())
	}
	if len(ents) != 1 {
		log.Fatal("Invalid number of entities in GnuPG key file.")
	}
	return ents[0]
}

//---------------------------------------------------------------------
/*
 * Application entry point
 */
func main() {
	// welcome message
	fmt.Println("====================================")
	fmt.Println("HS2GPG: Convert Tor 'Hidden Service'")
	fmt.Println("        key to GnuPG subkey  -- v0.1")
	fmt.Println("        (c) 2014 by Bernd Fix    >Y<")
	fmt.Println("        Software licensed under GPL3")
	fmt.Println("====================================")

	// handle command line parameters and options
	flag.StringVar(&keyfile, "i", "private_key", "hidden service keyfile")
	flag.StringVar(&gpgkey, "o", "key.asc", "GnuPG private key file")
	flag.Parse()

	// read hiden service key
	subKey := readHiddenServiceKey(keyfile)
	
	// read GnuPG entity file
	ent := readGpgKey(gpgkey)
	pk := ent.PrivateKey
	for pk.Encrypted {
		fmt.Printf("Passphrase to unlock key: ")
		pp, _, err := bufio.NewReader(os.Stdin).ReadLine()
		if err != nil {
			continue
		}
		if err = pk.Decrypt(pp); err != nil {
			log.Fatal("[10]" + err.Error())
		}
		for _, sk := range ent.Subkeys {
			if err = sk.PrivateKey.Decrypt(pp); err != nil {
				log.Fatal("[11]" + err.Error())
			}
		}
	}

	// create a new GnuPG subkey
	now := time.Now()
	pubKey := packet.NewRSAPublicKey(now, &subKey.PublicKey)
	sig := packet.Signature{
		Hash: crypto.SHA256,
		PubKeyAlgo: pubKey.PubKeyAlgo,
	}
	
	if err := sig.SignKey(pubKey, pk, nil); err != nil {
		log.Fatal("[6]" + err.Error())
	}
	sub := openpgp.Subkey{
		PublicKey: pubKey,
		PrivateKey: packet.NewRSAPrivateKey(now, subKey),
		Sig: &sig,
	} 
	// add subkey to entity
	ent.Subkeys = append(ent.Subkeys, sub)

	// write new GnuPG key file
	fp, err := os.Create(gpgkey)
	if err != nil {
		log.Fatal("[7]" + err.Error())
	}
	defer fp.Close()
	ar, err := armor.Encode(fp, openpgp.PrivateKeyType, nil)
	if err != nil {
		log.Fatal("[8]" + err.Error())
	}
	if err = ent.SerializePrivate(ar, nil); err != nil {
		log.Fatal("[9]" + err.Error())
	}
}
