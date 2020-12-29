package adyen

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"time"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
)

type Adyen struct {
	rsa     *adrsa
	prefix  string
	version string

	rsaEncryptAesVal string
	//iv
	aesKey     []byte
	_tagSize   int
	_nonceSize int
	_debug     bool
	aesNonce   []byte
}

type Data struct {
	Number         string `json:"number"`
	Cvc            string `json:"cvc"`
	HolderName     string `json:"holderName"`
	ExpiryMonth    string `json:"expiryMonth"`
	ExpiryYear     string `json:"expiryYear"`
	Generationtime string `json:"generationtime"`
}

type Data2 struct {
	Number              string `json:"number"`
	Cvc                 string `json:"cvc"`
	HolderName          string `json:"holderName"`
	ExpiryMonth         string `json:"expiryMonth"`
	ExpiryYear          string `json:"expiryYear"`
	Generationtime      string `json:"generationtime"`
	Activate            string `json:"activate"`
	Deactivate          string `json:"deactivate"`
	InitializeCount     string `json:"initializeCount"`
	LuhnCount           string `json:"luhnCount"`
	LuhnOkCount         string `json:"luhnOkCount"`
	LuhnSameLengthCount string `json:"luhnSameLengthCount"`
	DfValue             string `json:"dfValue"`
}

type CardForm struct {
	Number              string `json:"number" validate:"required"`
	Holder              string `json:"holder" validate:"required"`
	Cvv                 string `json:"cvv" validate:"required"`
	ExpiryMonth         string `json:"expiry_month" validate:"required"`
	ExpiryYear          string `json:"expiry_year" validate:"required"`
	Activate            string `json:"activate"`
	InitializeCount     string `json:"initializeCount"`
	LuhnCount           string `json:"luhnCount"`
	LuhnOkCount         string `json:"luhnOkCount"`
	LuhnSameLengthCount string `json:"luhnSameLengthCount"`
	DfValue             string `json:"dfValue"`
}

func NewAdYen(publicKey string) *Adyen {
	yen := &Adyen{}
	yen.rsa = NewRsa()
	yen.prefix = "adyenjs_"
	yen.version = "0_1_18"
	yen.aesKey = make([]byte, 32)
	yen._tagSize = 8
	yen._nonceSize = 12

	//如果密钥错误直接推出
	err := yen.rsa.SetPublicKey(publicKey, 65537)
	if err != nil {
		panic(err)
	}
	yen.init()
	return yen
}

func (yen *Adyen) marshal(data interface{}) []byte {
	if reflect.TypeOf(data).String() == "string" {
		return []byte(data.(string))
	}
	bytes, _ := json.Marshal(data)
	return bytes
}

//validate order info
func (yen *Adyen) validate(card CardForm) (Data, error) {
	gt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	info := Data{
		Number:         card.Number,
		Cvc:            card.Cvv,
		HolderName:     card.Holder,
		ExpiryMonth:    card.ExpiryMonth,
		ExpiryYear:     card.ExpiryYear,
		Generationtime: gt,
	}
	//check card info
	if err := validateAdYenCardInfo(info); err != nil {
		return info, err
	}

	return info, nil
}

//encrypt
func (yen *Adyen) EncryptNew(card interface{}) (string, error) {
	bytes := yen.marshal(card)

	//1. init aes random key
	yen.init()

	//2. create ccm instance
	block, err := aes.NewCipher(yen.aesKey)
	if err != nil {
		return "", err
	}
	cmer, err := NewCCM(block, yen._tagSize, len(yen.aesNonce))
	if err != nil {
		return "", err
	}

	//3. aes encrypt data
	cipherBytes := cmer.Seal(nil, yen.aesNonce, bytes, nil)
	cipherBytes = append(yen.aesNonce, cipherBytes...) //追加
	cipherText := base64.StdEncoding.EncodeToString(cipherBytes)

	if yen._debug {
		fmt.Println("aes:", cipherText)
	}
	//4. rsa encrypt aes.key
	rsaCp, err := yen.rsa.Encrypt2(yen.aesKey, "base64")
	if err != nil {
		return "", err
	}

	if yen._debug {
		fmt.Println("rsa:", rsaCp)
		fmt.Println("rsa:", len(rsaCp))
	}

	//5. append data
	prefix := yen.prefix + yen.version + "$"
	arr := []string{prefix, rsaCp, "$", cipherText}
	return strings.Join(arr, ""), nil
}

func (yen *Adyen) Encrypt3(card Data2) (string, error) {
	// pre validate
	//data, err := yen.validate(card)
	bytes := yen.marshal(card)

	//1. init aes random key
	yen.init()

	//2. create ccm instance
	block, err := aes.NewCipher(yen.aesKey)
	if err != nil {
		return "", err
	}
	cmer, err := NewCCM(block, yen._tagSize, len(yen.aesNonce))
	if err != nil {
		return "", err
	}

	//3. aes encrypt data
	cipherBytes := cmer.Seal(nil, yen.aesNonce, bytes, nil)
	cipherBytes = append(yen.aesNonce, cipherBytes...) //追加
	cipherText := base64.StdEncoding.EncodeToString(cipherBytes)
	if yen._debug {
		fmt.Println("aes:", cipherText)
	}
	//4. rsa encrypt aes.key
	rsaCp, err := yen.rsa.Encrypt2(yen.aesKey, "base64")
	if err != nil {
		return "", err
	}
	if yen._debug {
		fmt.Println("rsa:", rsaCp)
		fmt.Println("rsa:", len(rsaCp))
	}

	//5. append data
	prefix := yen.prefix + yen.version + "$"
	arr := []string{prefix, rsaCp, "$", cipherText}
	return strings.Join(arr, ""), nil
}

//encrypt
func (yen *Adyen) Encrypt(card CardForm) (string, error) {
	// pre validate
	data, err := yen.validate(card)
	bytes := yen.marshal(data)

	//1. init aes random key
	yen.init()

	//2. create ccm instance
	block, err := aes.NewCipher(yen.aesKey)
	if err != nil {
		return "", err
	}
	cmer, err := NewCCM(block, yen._tagSize, len(yen.aesNonce))
	if err != nil {
		return "", err
	}

	//3. aes encrypt data
	cipherBytes := cmer.Seal(nil, yen.aesNonce, bytes, nil)
	cipherBytes = append(yen.aesNonce, cipherBytes...) //追加
	cipherText := base64.StdEncoding.EncodeToString(cipherBytes)

	if yen._debug {
		fmt.Println("aes:", cipherText)
	}
	//4. rsa encrypt aes.key
	rsaCp, err := yen.rsa.Encrypt2(yen.aesKey, "base64")
	if err != nil {
		return "", err
	}

	if yen._debug {
		fmt.Println("rsa:", rsaCp)
		fmt.Println("rsa:", len(rsaCp))
	}

	//5. append data
	prefix := yen.prefix + yen.version + "$"
	arr := []string{prefix, rsaCp, "$", cipherText}
	return strings.Join(arr, ""), nil
}

func (yen *Adyen) debug() {
	yen._debug = true
	yen.aesKey = []byte{
		211, 230, 56, 196, 255, 13, 107, 44,
		124, 11, 172, 57, 108, 47, 222, 207,
		139, 212, 162, 56, 51, 163, 147, 100,
		195, 176, 241, 192, 75, 86, 32, 68,
	}
	yen.aesNonce = []byte{
		32, 103, 85, 109, 226,
		169, 214, 87, 67, 166,
		9, 92,
	}
}
func (yen *Adyen) init() {
	if yen._debug {
		return
	}
	yen.aesKey = yen.random(32)
	yen.aesNonce = yen.random(12)

}
func (yen *Adyen) random(len int) []byte {
	ak := make([]byte, len)
	_, _ = rand.Read(ak)
	return ak
}

func validateAdYenCardInfo(data Data) error {
	return nil
}

// ccm represents a Counter with CBC-MAC with a specific key.
type ccm struct {
	b cipher.Block
	M uint8
	L uint8
}

const ccmBlockSize = 16

// CCM is a block cipher in Counter with CBC-MAC mode.
// Providing authenticated encryption with associated data via the cipher.AEAD interface.
type CCM interface {
	cipher.AEAD
	// MaxLength returns the maxium length of plaintext in calls to Seal.
	// The maximum length of ciphertext in calls to Open is MaxLength()+Overhead().
	// The maximum length is related to CCM's `L` parameter (15-noncesize) and
	// is 1<<(8*L) - 1 (but also limited by the maxium size of an int).
	MaxLength() int
}

var (
	errInvalidBlockSize = errors.New("ccm: NewCCM requires 128-bit block cipher")
	errInvalidTagSize   = errors.New("ccm: tagsize must be 4, 6, 8, 10, 12, 14, or 16")
	errInvalidNonceSize = errors.New("ccm: invalid nonce size")
)

// NewCCM returns the given 128-bit block cipher wrapped in CCM.
// The tagsize must be an even integer between 4 and 16 inclusive
// and is used as CCM's `M` parameter.
// The noncesize must be an integer between 7 and 13 inclusive,
// 15-noncesize is used as CCM's `L` parameter.
func NewCCM(b cipher.Block, tagsize, noncesize int) (CCM, error) {
	if b.BlockSize() != ccmBlockSize {
		return nil, errInvalidBlockSize
	}
	if tagsize < 4 || tagsize > 16 || tagsize&1 != 0 {
		return nil, errInvalidTagSize
	}
	lensize := 15 - noncesize
	if lensize < 2 || lensize > 8 {
		return nil, errInvalidNonceSize
	}
	c := &ccm{b: b, M: uint8(tagsize), L: uint8(lensize)}
	return c, nil
}

func (c *ccm) NonceSize() int { return 15 - int(c.L) }
func (c *ccm) Overhead() int  { return int(c.M) }
func (c *ccm) MaxLength() int { return maxlen(c.L, c.Overhead()) }

func maxlen(L uint8, tagsize int) int {
	max := (uint64(1) << (8 * L)) - 1
	if m64 := uint64(math.MaxInt64) - uint64(tagsize); L > 8 || max > m64 {
		max = m64 // The maximum lentgh on a 64bit arch
	}
	if max != uint64(int(max)) {
		return math.MaxInt32 - tagsize // We have only 32bit int's
	}
	return int(max)
}

// MaxNonceLength returns the maximum nonce length for a given plaintext length.
// A return value <= 0 indicates that plaintext length is too large for
// any nonce length.
func MaxNonceLength(pdatalen int) int {
	const tagsize = 16
	for L := 2; L <= 8; L++ {
		if maxlen(uint8(L), tagsize) >= pdatalen {
			return 15 - L
		}
	}
	return 0
}

func (c *ccm) cbcRound(mac, data []byte) {
	for i := 0; i < ccmBlockSize; i++ {
		mac[i] ^= data[i]
	}
	c.b.Encrypt(mac, mac)
}

func (c *ccm) cbcData(mac, data []byte) {
	for len(data) >= ccmBlockSize {
		c.cbcRound(mac, data[:ccmBlockSize])
		data = data[ccmBlockSize:]
	}
	if len(data) > 0 {
		var block [ccmBlockSize]byte
		copy(block[:], data)
		c.cbcRound(mac, block[:])
	}
}

var (
	errPlaintextTooLong = errors.New("ccm: plaintext too large")
)

func (c *ccm) tag(nonce, plaintext, adata []byte) ([]byte, error) {
	var mac [ccmBlockSize]byte

	if len(adata) > 0 {
		mac[0] |= 1 << 6
	}
	mac[0] |= (c.M - 2) << 2
	mac[0] |= c.L - 1
	if len(nonce) != c.NonceSize() {
		return nil, errInvalidNonceSize
	}
	if len(plaintext) > c.MaxLength() {
		return nil, errPlaintextTooLong
	}
	binary.BigEndian.PutUint64(mac[ccmBlockSize-8:], uint64(len(plaintext)))
	copy(mac[1:ccmBlockSize-c.L], nonce)
	c.b.Encrypt(mac[:], mac[:])

	var block [ccmBlockSize]byte
	if n := uint64(len(adata)); n > 0 {
		// First adata block includes adata length
		i := 2
		if n <= 0xfeff {
			binary.BigEndian.PutUint16(block[:i], uint16(n))
		} else {
			block[0] = 0xfe
			block[1] = 0xff
			if n < uint64(1<<32) {
				i = 2 + 4
				binary.BigEndian.PutUint32(block[2:i], uint32(n))
			} else {
				i = 2 + 8
				binary.BigEndian.PutUint64(block[2:i], n)
			}
		}
		i = copy(block[i:], adata)
		c.cbcRound(mac[:], block[:])
		c.cbcData(mac[:], adata[i:])
	}

	if len(plaintext) > 0 {
		c.cbcData(mac[:], plaintext)
	}

	return mac[:c.M], nil
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
// From crypto/cipher/gcm.go
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
// The plaintext must be no longer than MaxLength() bytes long.
//
// The plaintext and dst may alias exactly or not at all.
func (c *ccm) Seal(dst, nonce, plaintext, adata []byte) []byte {
	tag, err := c.tag(nonce, plaintext, adata)
	if err != nil {
		// The cipher.AEAD interface doesn't allow for an error return.
		panic(err) // nolint
	}

	var iv, s0 [ccmBlockSize]byte
	iv[0] = c.L - 1
	copy(iv[1:ccmBlockSize-c.L], nonce)
	c.b.Encrypt(s0[:], iv[:])
	for i := 0; i < int(c.M); i++ {
		tag[i] ^= s0[i]
	}
	iv[len(iv)-1] |= 1
	stream := cipher.NewCTR(c.b, iv[:])
	ret, out := sliceForAppend(dst, len(plaintext)+int(c.M))
	stream.XORKeyStream(out, plaintext)
	copy(out[len(plaintext):], tag)
	return ret
}

var (
	errOpen               = errors.New("ccm: message authentication failed")
	errCiphertextTooShort = errors.New("ccm: ciphertext too short")
	errCiphertextTooLong  = errors.New("ccm: ciphertext too long")
)

func (c *ccm) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(ciphertext) < int(c.M) {
		return nil, errCiphertextTooShort
	}
	if len(ciphertext) > c.MaxLength()+c.Overhead() {
		return nil, errCiphertextTooLong
	}

	var tag = make([]byte, int(c.M))
	copy(tag, ciphertext[len(ciphertext)-int(c.M):])
	ciphertextWithoutTag := ciphertext[:len(ciphertext)-int(c.M)]

	var iv, s0 [ccmBlockSize]byte
	iv[0] = c.L - 1
	copy(iv[1:ccmBlockSize-c.L], nonce)
	c.b.Encrypt(s0[:], iv[:])
	for i := 0; i < int(c.M); i++ {
		tag[i] ^= s0[i]
	}
	iv[len(iv)-1] |= 1
	stream := cipher.NewCTR(c.b, iv[:])

	// Cannot decrypt directly to dst since we're not supposed to
	// reveal the plaintext to the caller if authentication fails.
	plaintext := make([]byte, len(ciphertextWithoutTag))
	stream.XORKeyStream(plaintext, ciphertextWithoutTag)
	expectedTag, err := c.tag(nonce, plaintext, adata)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, errOpen
	}
	return append(dst, plaintext...), nil
}


type adrsa struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func (r *adrsa) SetPublicKey(pubHex string, e int) error {
	k := &rsa.PublicKey{}
	dec, err := hex.DecodeString(pubHex)
	if err != nil {
		return err
	}

	k.N = new(big.Int).SetBytes(dec)
	k.E = e
	r.publicKey = k
	return nil
}

func (r *adrsa) Encrypt(str string, encoding string) (string, error) {
	bytes := []byte(str)
	res, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, bytes)
	if err != nil {
		return "", err
	}
	//	if encoding == "base64" {
	return base64.StdEncoding.EncodeToString(res), nil
	//	}
	//	return hex.EncodeToString(res), nil
}

func (r *adrsa) Encrypt2(bytes []byte, encoding string) (string, error) {
	res, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, bytes)
	if err != nil {
		return "", err
	}
	//	if encoding == "base64" {
	return base64.StdEncoding.EncodeToString(res), nil
	//	}
	//	return hex.EncodeToString(res), nil
}
func NewRsa() *adrsa {
	rs := &adrsa{}
	return rs
}
