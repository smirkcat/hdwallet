package hdwallet

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

func RandSeed() string {
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	return mnemonic
}

var wallet *hdwallet.Wallet

func InitHdwallet(mnemonic string) {
	var err error
	wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		panic(err)
	}
}

// 路径
var pathdrive = "m/44'/60'/0'/0/%d"

func NewAddressIndex(index int, flag ...bool) (publicstr, privatestr string, address map[string]string, err error) {
	publicstr, privatestr, err = NewAddress(fmt.Sprintf(pathdrive, index))
	if err == nil && len(flag) > 0 && flag[0] {
		address = make(map[string]string)
		pub, _ := GetPublicKeyByHexString(publicstr)
		address["eth"] = PubkeyToAddressETH(*pub)
		address["tron"] = PubkeyToAddressTron(*pub)
	}
	return
}

func NewAddress(path string) (publicstr, privatestr string, err error) {
	var privateKey *ecdsa.PrivateKey
	if wallet != nil {
		path := hdwallet.MustParseDerivationPath(path)
		var account accounts.Account
		account, err = wallet.Derive(path, true)
		if err != nil {
			return
		}
		privateKey, err = wallet.PrivateKey(account)
	} else {
		privateKey, err = ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	}

	if err != nil {
		return
	}
	publicstr = PubkeyToHexString(privateKey.Public().(*ecdsa.PublicKey))
	privatestr = PrikeyToHexString(privateKey)
	return
}

func PrikeyToHexString(key *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.FromECDSA(key))
}

func PubkeyToHexString(key *ecdsa.PublicKey) string {
	return hex.EncodeToString(crypto.FromECDSAPub(key))
}

func GetPrivateKeyByHexString(privateKeyHexString string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(privateKeyHexString)
}

func GetPublicKeyByHexString(PublicKeyHexString string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, _ := hex.DecodeString(PublicKeyHexString)
	return crypto.UnmarshalPubkey(publicKeyBytes)
}

// 秘钥解析
func LoadPrivateKeyFromDecrypt(encode, pwd string) (account *ecdsa.PrivateKey, err error) {
	re, err1 := base64.StdEncoding.DecodeString(encode)
	if err != nil {
		err = err1
		return
	}
	md5sum := md5.Sum([]byte(pwd))
	result, err1 := AesDecrypt(re, md5sum[:])
	if err != nil {
		err = err1
		return
	}
	account, err = GetPrivateKeyByHexString(string(result))
	return
}

// 加密保存
func StorePrivateKeyToDecrypt(account *ecdsa.PrivateKey, password string) (encode string, err error) {
	prikey := PrikeyToHexString(account)
	md5sum := md5.Sum([]byte(password))
	result, err1 := AesEncrypt([]byte(prikey), md5sum[:])
	if err1 != nil {
		err = err1
		return
	}
	encode = base64.StdEncoding.EncodeToString(result)
	return
}
