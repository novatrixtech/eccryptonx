package eccryptonx

import (
	"encoding/hex"
	"log"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

//EncryptECWithPublicKey using EC (with secp256k1 parameters) public key in hexadecimal string format encrypt a string
func EncryptECWithPublicKey(pubKeyInHexaString, textToEncrypt string) (encryptedText string, err error) {
	err = nil
	pubKeyInHexaString = strings.TrimPrefix(pubKeyInHexaString, "0x")
	dst := make([]byte, hex.DecodedLen(len(pubKeyInHexaString)))
	chavePublicaEmInt, err := hex.Decode(dst, []byte(pubKeyInHexaString))
	if err != nil {
		log.Fatal("[EncryptECDSAWithPublicKey] Error decoding pubKey to Int: ", err.Error())
		return
	}
	dst = dst[:chavePublicaEmInt]

	//log.Printf("[EncryptECDSAWithPublicKey]  PubKey: %s\n", dst)
	chavePublicaECDSA, err := secp256k1.ParsePubKey(dst)
	if err != nil {
		log.Fatal("Error parsing PubKey:", err)
		return
	}

	out, err := secp256k1.Encrypt(chavePublicaECDSA, []byte(textToEncrypt))
	if err != nil {
		log.Fatal("[EncryptECDSAWithPublicKey] failed to encrypt: ", err)
		return
	}
	encryptedText = string(out)
	return
}
