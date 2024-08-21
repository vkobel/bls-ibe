package blsibe

import (
	"fmt"

	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
)

type SigningNetwork struct {
	Suite            pairing.Suite
	Scheme           sign.AggregatableScheme
	IndividualKeys   []*KeyPair
	NetworkPublicKey kyber.Point
}

type KeyPair struct {
	Public  kyber.Point
	Private kyber.Scalar
}

func BLSKeyGen() *KeyPair {
	suite := bls12381.NewBLS12381Suite()

	// We're using G1 keys here, but we could use G2 keys as well
	P := suite.G1().Point().Base()
	s := suite.G1().Scalar().Pick(random.New())
	pub := suite.G1().Point().Mul(s, P)

	return &KeyPair{
		Public:  pub,
		Private: s,
	}
}

// JUST FOR EXAMPLE, DO NOT USE IN PRODUCTION,
// REPLACE WITH REAL THRESHOLD SCHEME USING DKG
func NewSigningNetwork(nb int) (*SigningNetwork, error) {
	suite := bls12381.NewBLS12381Suite()

	// Signature will be on G2, but we could use G1 as well (depends on the keys in BLSKeyGen above)
	scheme := bls.NewSchemeOnG2(suite)

	keyPairs := make([]*KeyPair, nb)
	publicKeys := make([]kyber.Point, nb)

	for i := 0; i < nb; i++ {
		kp := BLSKeyGen()
		keyPairs[i] = kp
		publicKeys[i] = kp.Public
	}

	aggPubKey := scheme.AggregatePublicKeys(publicKeys...)

	if aggPubKey == nil {
		return nil, fmt.Errorf("failed to aggregate public keys")
	}

	return &SigningNetwork{
		Suite:            suite,
		Scheme:           scheme,
		NetworkPublicKey: aggPubKey,
		IndividualKeys:   keyPairs,
	}, nil
}

func (sn *SigningNetwork) Sign(msg []byte) ([]byte, error) {
	sigs := make([][]byte, len(sn.IndividualKeys))

	for i, kp := range sn.IndividualKeys {

		fmt.Println("Signing with node ", i)
		sig, err := sn.Scheme.Sign(kp.Private, msg)
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}

	fmt.Println("Aggregating signatures")
	aggregateSig, err := sn.Scheme.AggregateSignatures(sigs...)
	if err != nil {
		fmt.Println("Failed to aggregate signatures")
		return nil, err
	}
	return aggregateSig, nil
}

func (sn *SigningNetwork) Verify(msg, sig []byte) bool {
	err := sn.Scheme.Verify(sn.NetworkPublicKey, msg, sig)
	return err == nil
}

func (sn *SigningNetwork) IBEEncrypt(msg, id []byte) (*ibe.Ciphertext, error) {
	// Encrypt on G1: https://github.com/drand/kyber/blob/94dae51d79b4b0c2d2a9b9cc382b864cf3537783/encrypt/ibe/ibe.go#L49
	ciphertext, err := ibe.EncryptCCAonG1(sn.Suite, sn.NetworkPublicKey, id, msg)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (sn *SigningNetwork) IBEDecrypt(ciphertext *ibe.Ciphertext, id, signatureBytes []byte) ([]byte, error) {

	// Signatures are on G2 here
	sigGroup := sn.Suite.G2()
	sigPoint := sigGroup.Point()
	if err := sigPoint.UnmarshalBinary(signatureBytes); err != nil {
		return nil, err
	}

	// ciphertext is on G1
	msg, err := ibe.DecryptCCAonG1(sn.Suite, sigPoint, ciphertext)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
