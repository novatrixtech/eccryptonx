package eccryptonx

import (
	"encoding/hex"
	"log"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/ethereum/go-ethereum/crypto"
)

//DecryptWithECPrivateKey decrypt a text using EC (with secp256k1 parameters) private key
func DecryptWithECPrivateKey(privateKey, encryptedText string) (decryptedText string, err error) {
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(privateKey))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	chavePrivadaDecred := secp256k1.NewPrivateKey(chavePrivadaEmECDSA.D)
	if err != nil {
		log.Fatal("[DecryptWithECPrivateKey] Error generating private key from text: ", err)
		return
	}

	dec, err := secp256k1.Decrypt(chavePrivadaDecred, []byte(encryptedText))
	if err != nil {
		log.Fatal("[DecryptWithECPrivateKey] failed to decrypt:", err)
	}
	decryptedText = string(dec)
	return
}
