/*
 * `gpg2hs` converts GnuPG private keys into Tor hidden services parameter
 * files `hostname` (to hold the onion address of the hidden service)
 * and `private_key` (the RSA key used by the hidden service)
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
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
)

///////////////////////////////////////////////////////////////////////
// package-global variables

var (
	secring string
	pubring string
	keyid   string
	target  string
	verify  bool
	create  bool

	kId   uint64
	kName string
	kMode int = 0
	err   error
)

///////////////////////////////////////////////////////////////////////
// Main methods

/*
 * Print OpenPGP entity
 * @param e *openpgp.Entity - entity to be printed
 */
func printEntity(e *openpgp.Entity) {
	fmt.Printf("   KeyId: 0x%x\n", e.PrimaryKey.KeyId)
	for n, _ := range e.Identities {
		fmt.Printf("   UID: %s\n", n)
	}
}

//---------------------------------------------------------------------
/*
 * Expand filename/filepath
 * @param p string - path to be expanded
 * @return string - expanded path
 */
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("[1]" + err.Error())
		}
		return usr.HomeDir + string(os.PathSeparator) + p[2:]
	}
	return p
}

//---------------------------------------------------------------------
/*
 * Check if a key identifier matches the given specification
 * @param ki uint64 - key identifier (full size)
 * @uses kMode int - key identifier mode (string, uint32, uint64)
 * @uses kId uint64 - numeric key identifier (command line)
 * @return bool - key ids match
 */
func check(ki uint64) bool {
	if kMode == 1 {
		ki &= 0xFFFFFFFF
	}
	return ki == kId
}

//---------------------------------------------------------------------
/*
 * Get matching entites from a keyring
 * @param file string - name of keyring file
 * @uses kMode int - key identifier mode (string, uint32, uint64)
 * @uses kId uint64 - numeric key identifier
 * @uses kName string - string fragment in identity (case-sensitive)
 * @return openpgp.EntityList - list of matching entities
 */
func getMatchingEntities(file string) openpgp.EntityList {
	fp, err := os.Open(file)
	if err != nil {
		log.Fatal("[2]" + err.Error())
	}
	defer fp.Close()
	ents, err := openpgp.ReadKeyRing(fp)
	if err != nil {
		log.Fatal("[3]" + err.Error())
	}
	s := make(openpgp.EntityList, 0)
L1:
	for _, e := range ents {
		if kMode == 3 {
			for n, _ := range e.Identities {
				if strings.Index(n, kName) != -1 {
					s = append(s, e)
					continue L1
				}
			}
		} else {
			if check(e.PrimaryKey.KeyId) {
				s = append(s, e)
				continue
			}
			for _, sk := range e.Subkeys {
				if check(sk.PublicKey.KeyId) {
					s = append(s, e)
					continue L1
				}
			}
		}
	}
	return s
}

//---------------------------------------------------------------------
/*
 * Compute onion address from RSA public key
 * @param key *rsa.PublicKey - public key to be converted
 * @return string - resulting onion address
 */
func computeOnion(key *rsa.PublicKey) string {
	b, err := asn1.Marshal(*key)
	if err != nil {
		log.Fatal("[4]" + err.Error())
	}
	h := sha1.New()
	if _, err = h.Write(b); err != nil {
		log.Fatal("[5]" + err.Error())
	}
	r := h.Sum(nil)
	return strings.ToLower(base32.StdEncoding.EncodeToString(r)[:16])
}

//---------------------------------------------------------------------
/*
 * Application entry point
 */
func main() {
	// welcome message
	fmt.Println("====================================")
	fmt.Println("GPG2HS: Convert/verify GnuPG subkeys")
	fmt.Println("        for Tor Hidden Services v0.1")
	fmt.Println("        (c) 2014 by Bernd Fix    >Y<")
	fmt.Println("        Software licensed under GPL3")
	fmt.Println("====================================")

	// handle command line parameters and options
	flag.BoolVar(&verify, "v", false, "[verify] onion address from public key")
	flag.BoolVar(&create, "c", false, "[create] hidden service files")
	flag.StringVar(&secring, "s", "~/.gnupg/secring.gpg", "keyring with secret keys (create only)")
	flag.StringVar(&pubring, "p", "~/.gnupg/pubring.gpg", "keyring with public keys (verify only)")
	flag.StringVar(&keyid, "k", "", "key to be converted/verified (mandatory; either 0x0123ABCD or name)")
	flag.StringVar(&target, "t", ".", "target directory for output (create only)")
	flag.Parse()

	// determine the key identifier mode
	kSize := len(keyid)
	switch {
	case kSize == 0:
		flag.Usage()
		log.Fatal("Missing key identifier!")
	case strings.HasPrefix(keyid, "0x"):
		kId, err = strconv.ParseUint(keyid[2:], 16, 64)
		if err != nil {
			log.Fatal("[6]" + err.Error())
		}
		switch kSize {
		case 10:
			kMode = 1
		case 18:
			kMode = 2
		default:
			log.Fatal("Invalid length of numeric key identifier")
		}
	default:
		kName = keyid
		kMode = 3
	}

	if verify {
		// verify public key onions
		s := getMatchingEntities(expandPath(pubring))
		for i, e := range s {
			fmt.Printf("Key #%d:\n", i+1)
			printEntity(e)
			for _, sk := range e.Subkeys {
				switch sk.PublicKey.PublicKey.(type) {
				case *rsa.PublicKey:
					pk := sk.PublicKey.PublicKey.(*rsa.PublicKey)
					if pk.N.BitLen() != 1024 {
						continue
					}
					onion := computeOnion(pk)
					fmt.Printf("   ==> Onion address is '" + onion + ".onion'\n")
				}
			}
		}
	} else if create {
		// create Tor hidden service parameter files
		s := getMatchingEntities(expandPath(secring))

		// check result set for single matching key
		switch len(s) {
		case 0:
			log.Fatal("No matching key found.")
		case 1:
			fmt.Println("Key found:")
			printEntity(s[0])
		case 2:
			fmt.Println("Keys found:")
			for i, e := range s {
				fmt.Printf("Key #%d:\n", i+1)
				printEntity(e)
			}
			log.Fatal("Ambigious key identifier - please narrow search")
		}

		// select subkey
		subs := make([]openpgp.Subkey, 0)
		var sk openpgp.Subkey
		for _, sk = range s[0].Subkeys {
			switch sk.PublicKey.PublicKey.(type) {
			case *rsa.PublicKey:
				pk := sk.PublicKey.PublicKey.(*rsa.PublicKey)
				if pk.N.BitLen() != 1024 {
					continue
				}
				subs = append(subs, sk)
				fmt.Printf("Suitable Subkey #%d: 0x%x\n", len(subs), sk.PublicKey.KeyId)
			}
		}
		switch len(subs) {
		case 0:
			log.Fatal("No suitable subkeys found for Hidden Service")
		case 1:
			sk = subs[0]
			fmt.Printf("Using subkey 0x%x\n", sk.PublicKey.KeyId)
		default:
			found := false
			for _, sk := range subs {
				if check(sk.PublicKey.KeyId) {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("Multiple suitable subkeys found -- specify key identifier directly")
			}
		}

		// correct target path specification
		target = expandPath(target)
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}

		// write `hostname` file
		onion := computeOnion(s[0].PrimaryKey.PublicKey.(*rsa.PublicKey))
		fp, err := os.Create(target + "hostname")
		if err != nil {
			log.Fatal("[7]" + err.Error())
		}
		fp.WriteString(onion + ".onion\n")
		fp.Close()

		// unlock private key (if encrypted)
		pk := s[0].PrivateKey
		for pk.Encrypted {
			fmt.Printf("Passphrase to unlock key: ")
			pp, _, err := bufio.NewReader(os.Stdin).ReadLine()
			if err != nil {
				continue
			}
			if err = pk.Decrypt(pp); err != nil {
				log.Fatal("[8]" + err.Error())
			}
			for _, s := range s[0].Subkeys {
				if err = s.PrivateKey.Decrypt(pp); err != nil {
					log.Fatal("[9]" + err.Error())
				}
			}
		}
		if pk.PrivateKey == nil {
			log.Fatal("No private key data found")
		}

		// write `private_key` file from selected subkey
		hsPrv := sk.PrivateKey.PrivateKey.(*rsa.PrivateKey)
		hsBytes := x509.MarshalPKCS1PrivateKey(hsPrv)
		outK := base64.StdEncoding.EncodeToString(hsBytes)
		fp, err = os.Create(target + "private_key")
		if err != nil {
			log.Fatal("[10]" + err.Error())
		}
		fp.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
		for {
			if len(outK) > 64 {
				fp.WriteString(outK[:64] + "\n")
				outK = outK[64:]
			} else {
				fp.WriteString(outK + "\n")
				break
			}
		}
		fp.WriteString("-----END RSA PRIVATE KEY-----\n")
		fp.Close()

		// output generated onion address
		fmt.Println()
		fmt.Println("Onion address: " + onion + ".onion")
	} else {
		flag.Usage()
		log.Fatal("[verify] or [create] mandatory.")
	}
}
