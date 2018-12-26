package rsablock

import (
	"errors"
	"strings"
	"testing"
)

func init() {
	var err error
	rsak, err = NewRSAKey([]byte(Pirvatekey))
	if err != nil {
		panic(err)
	}
}

var Pubkey = `-----BEGIN RSA Public Key-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANQAOvQJ61YpEwn0amjkzkjmancLpCOe
BLR9X3PRbq/niQ+5gwGOvgAyaaAgY1iv80hyasoE+lohmIABoldDNV0CAwEAAQ==
-----END RSA Public Key-----
`

var Pirvatekey = `-----BEGIN RSA Private Key-----
MIIBOQIBAAJBANQAOvQJ61YpEwn0amjkzkjmancLpCOeBLR9X3PRbq/niQ+5gwGO
vgAyaaAgY1iv80hyasoE+lohmIABoldDNV0CAwEAAQJADKD24hK1MizANZeZvyXi
I/WV4gGPhY+kOBw/02ZmcZP9jLyrOhyKd5YSG3/0GDOF1oY6yw/Vei87I6QSfKD7
AQIhAPRTVJHNCeuC6QT5HnqjRTJBdjg59jnxe31zHcoV6wVbAiEA3iF+pkTL3cJ/
UJ1uAE4ZC+jRGD+fgM0PuUnLT9Da1acCIEIBVSKCewCWAC+owXQuMZ5vEuoDtqJW
u57bf5u9qh1rAiBUVb8x/Vixf1C7GKpU71HPFbudSzqRuklH/d51FUSgbQIgDxQt
rMmt4Qzy4EdWidSwvXW4osRmdmPJZScVGw7t+Lw=
-----END RSA Private Key-----`
var plainText = Pirvatekey + Pubkey
var rsak *RSAKey

func Test_NewRSAKey(t *testing.T) {
	_, err := NewRSAKey([]byte(Pirvatekey))
	if err != nil {
		t.Error(err)
	}

}

func Test_EncryptDecrypt(t *testing.T) {
	if rsak == nil {
		t.Error(errors.New("创建 失败"))
	}

	ss, err := rsak.BlockRSAEncrypt([]byte(plainText))
	if err != nil {
		t.Error(err)
	}

	str, err := rsak.BlockRSADecrypt(ss)
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(string(str), plainText) != 0 {
		t.Error(errors.New("加解密验证失败"))
	}
}
