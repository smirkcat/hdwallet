package hdwallet

import (
	"testing"
)

var mnemonic = "tag volcano eight thank tide danger coast health above argue embrace heavy"

func TestPubkey(t *testing.T) {
	InitHdwallet(mnemonic)
	publicstr, privatestr, _ := NewAddress("m/44'/60'/0'/0/0")

	t.Log(publicstr)
	t.Log(privatestr)

	pub, err := GetPublicKeyByHexString(publicstr)
	if err == nil {
		t.Log(PubkeyToHexString(pub))
		t.Log(PubkeyToAddressETH(*pub))
		t.Log(PubkeyToAddressTron(*pub))
	}

	pri, _ := GetPrivateKeyByHexString(privatestr)

	encode, err := StorePrivateKeyToDecrypt(pri, "ceshi")
	if err == nil {
		t.Log(encode)
	}

	_, err = LoadPrivateKeyFromDecrypt(encode, "ceshi")

	if err == nil {
		t.Log("dcode success")
	}
}

func TestRandSeed(t *testing.T) {
	t.Log(RandSeed())
}
