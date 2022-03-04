package hdwallet

import (
	"crypto/ecdsa"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// ETH系列地址
func PrikeyToAddressETH(privateKey *ecdsa.PrivateKey) string {
	return strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).String())
}

func PubkeyToAddressETH(pubKey ecdsa.PublicKey) string {
	return strings.ToLower(crypto.PubkeyToAddress(pubKey).String())
}
