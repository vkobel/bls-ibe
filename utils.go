package blsibe

import (
	"fmt"

	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

const (
	cipherVLen = 32
	cipherWLen = 32
)

// CiphertextToBytes converts a ciphertext value to a set of bytes.
func CiphertextToBytes(suite pairing.Suite, ciphertext *ibe.Ciphertext) ([]byte, error) {
	kyberPoint, err := ciphertext.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber point: %w", err)
	}

	kyberPointLen := ciphertext.U.MarshalSize()
	if kyberPointLen != suite.G1().PointLen() {
		return nil, fmt.Errorf("unsupported type (MarshalSize %d) for U: %T", kyberPointLen, ciphertext.U)
	}

	b := make([]byte, kyberPointLen+cipherVLen+cipherWLen)
	copy(b, kyberPoint)
	copy(b[kyberPointLen:], ciphertext.V)
	copy(b[kyberPointLen+cipherVLen:], ciphertext.W)

	return b, nil
}

// BytesToCiphertext converts bytes to a ciphertext.
func BytesToCiphertext(suite pairing.Suite, b []byte) (*ibe.Ciphertext, error) {
	kyberPointLen := suite.G1().PointLen()
	if tot := kyberPointLen + cipherVLen + cipherWLen; len(b) != tot {
		return nil, fmt.Errorf("incorrect length: exp: %d got: %d", tot, len(b))
	}

	kyberPoint := make([]byte, kyberPointLen)
	copy(kyberPoint, b[:kyberPointLen])

	cipherV := make([]byte, cipherVLen)
	copy(cipherV, b[kyberPointLen:kyberPointLen+cipherVLen])

	cipherW := make([]byte, cipherVLen)
	copy(cipherW, b[kyberPointLen+cipherVLen:])

	u := suite.G1().Point()
	if err := u.UnmarshalBinary(kyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber point (type %T): %w", suite.G1(), err)
	}

	ct := ibe.Ciphertext{
		U: u,
		V: cipherV,
		W: cipherW,
	}

	return &ct, nil
}
