package main

import (
	"bufio"
	"code.google.com/p/go.crypto/openpgp"
	"crypto/sha1"
	"crypto/rsa"
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

var (
	secring string
	pubring string
	keyid string
	target string
	verify bool
	create bool
	
	kId uint64
	kName string
	kMode int = 0
	err error
)

func printEntity(e *openpgp.Entity) {
	fmt.Printf("   KeyID: 0x%d\n", e.PrimaryKey.KeyId)
	for n, _ := range e.Identities {
		fmt.Printf("   UID: %s\n", n)
	}
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("[1]"+err.Error())
		}
		return usr.HomeDir + string(os.PathSeparator) + p[2:]
	}
	return p
}

func getMatchingEntities(file string) openpgp.EntityList {
	fp, err := os.Open(file)
	if err != nil {
		log.Fatal("[2]"+err.Error())
	}
	defer fp.Close()
	ents, err := openpgp.ReadKeyRing(fp)
	if err != nil {
		log.Fatal("[3]"+err.Error())
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
			kTest := e.PrimaryKey.KeyId
			if kMode == 1 {
				kTest &= 0xFFFFFFFF
			}
			if kTest == kId {
				s = append(s, e)
				continue L1
			}
		}	
	}
	return s
}

func computeOnion(key *rsa.PublicKey) string {
	b, err := asn1.Marshal(*key)
	if err != nil {
		log.Fatal("[4]"+err.Error())
	}
	h := sha1.New()
	if _, err = h.Write(b); err != nil {
		log.Fatal("[5]"+err.Error())
	}
	r := h.Sum(nil)
	return strings.ToLower(base32.StdEncoding.EncodeToString(r)[:16])
}

func main() {
	flag.BoolVar(&verify, "v", false, "[verify] onion address from public key")
	flag.BoolVar(&create, "c", false, "[create] hidden service files")
	flag.StringVar(&secring, "s", "~/.gnupg/secring.gpg", "keyring with secret keys (create only)")
	flag.StringVar(&pubring, "p", "~/.gnupg/pubring.gpg", "keyring with public keys (verify only)")
	flag.StringVar(&keyid, "k", "", "key to be converted/verified (mandatory; either 0x0123ABCD or name)")
	flag.StringVar(&target, "t", ".", "target directory for output (create only)")
	flag.Parse()

	kSize := len(keyid)
	switch {
	case kSize == 0:
		flag.Usage()
		log.Fatal("Missing key identifier!")
	case strings.HasPrefix(keyid, "0x"):
		kId, err = strconv.ParseUint(keyid[2:],16,64)
		if err != nil {
			log.Fatal("[6]"+err.Error())
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
		s := getMatchingEntities(expandPath(pubring))
		for i, e := range s {
			fmt.Printf("Key #%d:\n",i+1) 
			printEntity(e)
			onion := computeOnion(e.PrimaryKey.PublicKey.(*rsa.PublicKey))
			fmt.Printf("   ==> Onion address is '"+onion+".onion'\n")
		}
	} else if create {
		s := getMatchingEntities(expandPath(secring))
		switch len(s) {
		case 0:
			log.Fatal("No matching key found.")
		case 1:
			fmt.Println("Key found:")
			printEntity(s[0])
		case 2:
			fmt.Println("Keys found:")
			for i, e := range s {
				fmt.Printf("Key #%d:\n",i+1) 
				printEntity(e)
			}
			log.Fatal("Ambigious key identifier - please narrow search")
		}
		
		target = expandPath(target)
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}

		onion := computeOnion(s[0].PrimaryKey.PublicKey.(*rsa.PublicKey))
		fp, err := os.Create (target + "hostname")
		if err != nil {
			log.Fatal("[7]"+err.Error())
		}
		fp.WriteString(onion+".onion\n")
		fp.Close()
	
		pk := s[0].PrivateKey
		for pk.Encrypted {
			fmt.Printf("Passphrase to unlock key: ")
			pp, _, err := bufio.NewReader(os.Stdin).ReadLine()
			if err != nil {
				continue
			}
			if err = pk.Decrypt(pp); err != nil {
				log.Fatal("[8]"+err.Error())
			}
		}
		if pk.PrivateKey == nil {
			log.Fatal("No private key data found")
		}
		hsPrv := pk.PrivateKey.(*rsa.PrivateKey)
		hsBytes := x509.MarshalPKCS1PrivateKey(hsPrv)
		outK := base64.StdEncoding.EncodeToString(hsBytes)
		fp, err = os.Create (target + "private_key")
		if err != nil {
			log.Fatal("[1]"+err.Error())
		}
		fp.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
		for {
			if len(outK) > 64 {
				fp.WriteString(outK[:64]+"\n")
				outK = outK[64:]
			} else {
				fp.WriteString(outK+"\n")
				break
			}
		}
		fp.WriteString("-----END RSA PRIVATE KEY-----\n")
		fp.Close()
		
		fmt.Println()
		fmt.Println("Onion address: " + onion + ".onion")
	} else {
		flag.Usage()
		log.Fatal("[verify] or [create] mandatory.")
	}
}
