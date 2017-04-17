package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
)

// interface for Session.Data serialization
type SessionDataCoder interface {
	Encode(data interface{}) ([]byte, error)
	Decode(dest interface{}, data []byte) error
}

// JSON data serialization
type JSONCoder struct {
}

// JSON Coder instantiator
func NewJSONCoder() *JSONCoder {
	return &JSONCoder{}
}

// implements Encode function of SessionDataCoder interface
func (g *JSONCoder) Encode(src interface{}) ([]byte, error) {
	byts, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	return byts, nil
}

// implements Decode function of SessionDataCoder interface
func (g *JSONCoder) Decode(dst interface{}, src []byte) error {
	err := json.Unmarshal(src, dst)
	if err != nil {
		return err
	}
	return nil
}

// Cookie Store struct
type CookieStore struct {
	hashAlgo func() hash.Hash
	hashSize int
	hashKey  []byte
	encKey   []byte

	dataEnc       SessionDataCoder
	dataAllocator func() interface{} // a
}

// Instantiate a cookie store
// PARAMETERS
// hashKey             : keys to use in HMAC authentication
// encKey16or32        : encryption keys used in AES encryption algorithm; optional
// enc                 : an implementation of SessionDataCoder interface.  this will be used for Session.Data serialization/deserialization
// sessionDataAllocator: a function that must return an instance of Session.Data; this to avoid type map instance
//:
func NewCookieStore(hashKey, encKey16or32 []byte, enc SessionDataCoder, sessionDataAllocator func() interface{}) (*CookieStore, error) {

	ln := len(encKey16or32)

	if ln != 0 && ln != 16 && ln != 32 {
		// invalid encKey
		return nil, errors.New("invalid encryption key length;")
	}

	if (enc == nil && sessionDataAllocator != nil) || (enc != nil && sessionDataAllocator == nil) {
		return nil, errors.New("DataEncoder is nil or sessionDataAllocator is nil")
	}

	cs := &CookieStore{hashKey: hashKey, encKey: encKey16or32, dataEnc: enc, dataAllocator: sessionDataAllocator}
	// default hash algorithm
	cs.hashAlgo = sha1.New
	cs.hashSize = sha1.Size
	return cs, nil
}

// Saves a session by returning a value for cookie savings
func (cs *CookieStore) Put(s *Session) (string, error) {
	if s == nil {
		return "", errors.New("session is nil or empty")
	}
	loginLen := len(s.LoginName)
	if loginLen > 255 {
		return "", errors.New("login name is too long")
	}

	var serData []byte
	var serDataLen int
	//serialized Session.Data
	if s.Data != nil {
		var err error
		serData, err = cs.dataEnc.Encode(s.Data)
		if err != nil {
			return "", err
		}
		serDataLen = len(serData)
	}
	// buffer data sequence
	//buffer length = Session.Expiry(4) + Session.Flag(8) + len(Session.LoginName) + Session.LoginName + Session.Data + hashSize
	buffLen := 13 + loginLen + serDataLen + cs.hashSize
	buff := make([]byte, buffLen)

	// fill buff with expiry
	copy(buff, Uint32ToBytes(s.Expiry))

	// fill buff with flag value
	copy(buff[4:], Uint64ToBytes(s.Flags))

	// fill with loginName
	buff[12] = byte(loginLen)
	copy(buff[13:], []byte(s.LoginName))

	// fill data with variable data
	copy(buff[13+loginLen:], serData)

	actualDataLen := 13 + loginLen + serDataLen

	mac := hmac.New(cs.hashAlgo, cs.hashKey)
	mac.Write(buff[0:actualDataLen])

	// put the hashed result at end of data
	copy(buff[actualDataLen:], mac.Sum(nil))

	// encrypt
	if cs.encKey != nil {
		var err error
		// encrypt the data
		err = EncryptAES(buff, cs.encKey, buff)

		if err != nil {
			return "", err
		}
	} else {

	}
	// return the base64 encoded data
	return base64.URLEncoding.EncodeToString(buff), nil
}

func (cs *CookieStore) Get(cookieVal string) (*Session, error) {

	byts, err := base64.URLEncoding.DecodeString(cookieVal)

	if err != nil {
		return nil, err
	}

	dataLen := len(byts)

	if dataLen < 13+cs.hashSize {
		return nil, errors.New("session cookie is invalid length")
	}

	rawData := make([]byte, dataLen)

	var err2 error
	if cs.encKey != nil {
		err2 = DecryptAES(rawData, cs.encKey, byts)
		if err2 != nil {
			return nil, err2
		}

	} else {
		rawData = byts
	}

	mac := hmac.New(cs.hashAlgo, cs.hashKey)
	mac.Write(rawData[0 : dataLen-cs.hashSize])
	hSum := mac.Sum(nil)

	s := new(Session)

	if !bytes.Equal(hSum, rawData[dataLen-cs.hashSize:]) {
		s.State = EXPIRED //TAMPERED
		return s, errors.New("Session cookie was tampered.")
	}
	s.Expiry, _ = BytesToUint32(rawData[0:4])
	s.Flags, _ = BytesToUint64(rawData[4:12])

	loginLen := rawData[12]
	s.LoginName = string(rawData[13 : 13+loginLen])

	// extract Session.Data
	if len(rawData[13+loginLen:dataLen-cs.hashSize]) > 0 {
		s.Data = cs.dataAllocator()
		err = cs.dataEnc.Decode(s.Data, rawData[13+loginLen:dataLen-cs.hashSize])

		if err != nil {
			return nil, err
		}
	}
	return s, nil

}

func (cs *CookieStore) Delete(sessID string) error {
	// just return nil; session data was saved as cookie;
	return nil
}

func Uint16ToBytes(i uint16) []byte {
	dst := make([]byte, 2)
	dst[0] = byte(i >> 8)
	dst[1] = byte(i & 0x00FF)
	return dst

}

func Uint32ToBytes(i uint32) []byte {
	dst := make([]byte, 4)
	dst[0] = byte(i >> 24)
	dst[1] = byte((i & 0x00FF0000) >> 16)
	dst[2] = byte((i & 0x0000FF00) >> 8)
	dst[3] = byte(i & 0x000000FF)
	return dst
}

func Uint64ToBytes(i uint64) []byte {
	dst := make([]byte, 8)
	dst[0] = byte(i >> 56)
	dst[1] = byte((i & 0x00FF000000000000) >> 48)
	dst[2] = byte((i & 0x0000FF0000000000) >> 40)
	dst[3] = byte((i & 0x000000FF00000000) >> 32)

	dst[4] = byte((i & 0x00000000FF000000) >> 24)
	dst[5] = byte((i & 0x0000000000FF0000) >> 16)
	dst[6] = byte((i & 0x000000000000FF00) >> 8)
	dst[7] = byte(i & 0x00000000000000FF)
	return dst
}

func BytesToUint16(b []byte) (uint16, error) {
	var t uint16
	if len(b) != 2 {
		return 0, errors.New("array length must be 4")
	}
	t = (uint16(b[0]) << 8) | uint16(b[1])

	return t, nil

}

func BytesToUint32(b []byte) (uint32, error) {
	var t uint32
	if len(b) != 4 {
		return 0, errors.New("array length must be 4")
	}
	t = (uint32(b[0]) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | uint32(b[3])

	return t, nil

}

func BytesToUint64(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, errors.New("array length must be 8")
	}
	t := (uint64(b[0]) << 56) | (uint64(b[1]) << 48) | (uint64(b[2]) << 40) | (uint64(b[3]) << 32) | (uint64(b[4]) << 24) | (uint64(b[5]) << 16) | (uint64(b[6]) << 8) | uint64(b[7])

	return t, nil

}

var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func EncryptAES(dst, key16or32, data []byte) error {
	c, err := aes.NewCipher(key16or32)
	if err != nil {
		return err
	}

	cfb := cipher.NewCFBEncrypter(c, commonIV)

	cfb.XORKeyStream(dst, data)
	return nil
}

func DecryptAES(dst, key16or32, data []byte) error {
	c, err2 := aes.NewCipher(key16or32)
	if err2 != nil {
		return err2
	}

	cfbdec := cipher.NewCFBDecrypter(c, commonIV)

	cfbdec.XORKeyStream(dst, data)
	return nil
}
