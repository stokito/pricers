package doubleclick

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/benjaminch/pricers/helpers"
)

var ErrWrongSize = errors.New("Encrypted price is not 38 chars")
var ErrWrongSignature = errors.New("Failed to decrypt")

// DoubleClickPricer implementing price encryption and decryption
// Specs : https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price
type DoubleClickPricer struct {
	encryptionKeyRaw string
	integrityKeyRaw  string
	encryptionKey    hash.Hash
	integrityKey     hash.Hash
	keyDecodingMode  helpers.KeyDecodingMode
	scaleFactor      float64
	isDebugMode      bool
}

// NewDoubleClickPricer returns a DoubleClickPricer struct.
// Keys are either base 64 websafe of hexa. keyDecodingMode
// should be used to specify how keys should be decoded.
// Factor the clear price will be multiplied by before encryption.
// from specs, scaleFactor is 1,000,000, but you can set something else.
// Be aware that the price is stored as an int64 so depending on the digits
// precision you want, picking a scale factor smaller than 1,000,000 may lead
// to price to be rounded and loose some digits precision.
func NewDoubleClickPricer(
	encryptionKey string,
	integrityKey string,
	isBase64Keys bool,
	keyDecodingMode helpers.KeyDecodingMode,
	scaleFactor float64,
	isDebugMode bool) (*DoubleClickPricer, error) {
	var err error
	var encryptingFun, integrityFun hash.Hash

	encryptingFun, err = helpers.CreateHmac(encryptionKey, isBase64Keys, keyDecodingMode)
	if err != nil {
		return nil, err
	}
	integrityFun, err = helpers.CreateHmac(integrityKey, isBase64Keys, keyDecodingMode)
	if err != nil {
		return nil, err
	}

	if isDebugMode {
		fmt.Println("Keys decoding mode : ", keyDecodingMode)
		fmt.Println("Encryption key : ", encryptionKey)
		encryptionKeyHexa, err := hex.DecodeString(encryptionKey)
		if err != nil {
			encryptionKeyHexa = []byte(encryptionKey)
		}
		fmt.Println("Encryption key (bytes) : ", []byte(encryptionKeyHexa))
		fmt.Println("Integrity key : ", integrityKey)
		integrityKeyHexa, err := hex.DecodeString(integrityKey)
		if err != nil {
			integrityKeyHexa = []byte(integrityKey)
		}
		fmt.Println("Integrity key (bytes) : ", []byte(integrityKeyHexa))
	}

	return &DoubleClickPricer{
			encryptionKeyRaw: encryptionKey,
			integrityKeyRaw:  integrityKey,
			encryptionKey:    encryptingFun,
			integrityKey:     integrityFun,
			keyDecodingMode:  keyDecodingMode,
			scaleFactor:      scaleFactor,
			isDebugMode:      isDebugMode},
		nil
}

// Encrypt encrypts a clear price and a given seed.
func (dc *DoubleClickPricer) Encrypt(seed string, price float64) (string, error) {
	var (
		iv        [16]byte
		encoded   [8]byte
		signature []byte
	)

	data := helpers.ApplyScaleFactor(price, dc.scaleFactor)

	// Create Initialization Vector from seed
	iv = md5.Sum([]byte(seed))

	//pad = hmac(e_key, iv), first 8 bytes
	pad := helpers.HmacSum(dc.encryptionKey, iv[:], nil)[:8]

	// signature = hmac(i_key, data || iv), first 4 bytes
	signature = helpers.HmacSum(dc.integrityKey, data[:], iv[:])[:4]

	// enc_data = pad <xor> data
	for i := range data {
		encoded[i] = pad[i] ^ data[i]
	}

	// final_message = WebSafeBase64Encode( iv || enc_price || signature )
	return base64.RawURLEncoding.EncodeToString(append(append(iv[:], encoded[:]...), signature...)), nil
}

// Decrypt decrypts an encrypted price.
func (dc *DoubleClickPricer) Decrypt(encryptedPrice string) (float64, error) {
	buf := make([]byte, 28)
	priceInMicro, err := dc.DecryptRaw([]byte(encryptedPrice), buf)
	price := float64(priceInMicro) / dc.scaleFactor
	return price, err
}

// DecryptRaw decrypts an encrypted price.
// It returns the price as integer in micros without applying a scaleFactor
// You must pass a buffer for decoder so that can reused again to avoid allocation
func (dc *DoubleClickPricer) DecryptRaw(encryptedPrice []byte, buf []byte) (uint64, error) {
	var err error

	// Decode base64 url
	// Just to be safe remove padding if it was added by mistake
	encryptedPrice = bytes.TrimRight(encryptedPrice, "=")
	if len(encryptedPrice) != 38 {
		return 0, ErrWrongSize
	}
	_, err = base64.RawURLEncoding.Decode(buf, encryptedPrice)
	if err != nil {
		return 0, err
	}
	decoded := buf

	// Get elements
	iv := decoded[0:16]
	p := binary.BigEndian.Uint64(decoded[16:24])
	signature := binary.BigEndian.Uint32(decoded[24:28])

	// pad = hmac(e_key, iv)
	pad := binary.BigEndian.Uint64(helpers.HmacSum(dc.encryptionKey, iv, nil)[:8])

	// priceMicro = p <xor> pad
	priceInMicros := pad ^ p
	priceMicro := [8]byte{}
	binary.BigEndian.PutUint64(priceMicro[:], priceInMicros)

	// conf_sig = hmac(i_key, data || iv)
	confirmationSignature := binary.BigEndian.Uint32(helpers.HmacSum(dc.integrityKey, priceMicro[:], iv)[:4])

	// success = (conf_sig == sig)
	if confirmationSignature != signature {
		return 0, ErrWrongSignature
	}

	return priceInMicros, nil
}
