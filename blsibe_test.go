package blsibe

import (
	"encoding/base64"
	"fmt"
	"testing"
)

// write simple test for BLSKeyGen
func TestBlsKeyGen(t *testing.T) {
	kp := BLSKeyGen()
	if kp == nil {
		t.Error("BLSKeyGen failed")
	}
}

func TestGenSigningNetwork(t *testing.T) {
	sn, err := NewSigningNetwork(4)
	if err != nil {
		t.Error("NewSigningNetwork failed")
	}

	// marshal the public key
	pubKeyBytes, err := sn.NetworkPublicKey.MarshalBinary()
	if err != nil {
		t.Error("MarshalBinary failed")
	}
	fmt.Println("Public Key:", base64.StdEncoding.EncodeToString(pubKeyBytes))
}

func TestSign(t *testing.T) {
	sn, err := NewSigningNetwork(14)
	if err != nil {
		t.Error("NewSigningNetwork failed")
	}

	// sign a message
	msg := []byte("Hello, BLSIBE!")
	sig, err := sn.Sign(msg)
	if err != nil {
		t.Error(err)
	}

	// print the network pubkey
	pubkey, err := sn.NetworkPublicKey.MarshalBinary()
	if err != nil {
		t.Error("MarshalBinary failed")
	}
	fmt.Println("Network public key:", base64.StdEncoding.EncodeToString(pubkey))

	// print each public key from the network
	for i, kp := range sn.IndividualKeys {
		pubkey, err := kp.Public.MarshalBinary()
		if err != nil {
			t.Error("MarshalBinary failed")
		}
		fmt.Println("Public key ", i, ":", base64.StdEncoding.EncodeToString(pubkey))
	}

	// verify the signature
	if !sn.Verify(msg, sig) {
		t.Error(err)
	}

	fmt.Printf("Signature '%s' is verified against the network pubkey\n", base64.StdEncoding.EncodeToString(sig))
}

func TestIBEEncryptDecrypt(t *testing.T) {
	sn, err := NewSigningNetwork(3)
	if err != nil {
		t.Error("NewSigningNetwork failed")
	}

	// encrypt a message
	// ====> RN MESSAGE NEEDS TO BE 16 CHARS FOR THE ENCODING TO WORK,
	msg := []byte("msg be 16 chars!")
	id := []byte("{policy: True}")

	// TODO: ENCRYPT A WRAPPING SYMMETRIC KEY INSTEAD OF THE MESSAGE
	// Then same for decryption

	ciphertext, err := sn.IBEEncrypt(msg, id)
	if err != nil {
		t.Error(err)
	}

	ciphertextBytes, err := CiphertextToBytes(sn.Suite, ciphertext)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("cipherText:", base64.StdEncoding.EncodeToString(ciphertextBytes))

	// todo: eval the policy on each signer.....

	// but here we just blind sign on all signing network for now
	sigBytes, err := sn.Sign(id)
	if err != nil {
		t.Error(err)
	}

	// perfrom verification of the signature
	if !sn.Verify(id, sigBytes) {
		t.Error(err)
	}
	fmt.Println("Signature verified")

	ciphertextUnmarshalled, err := BytesToCiphertext(sn.Suite, ciphertextBytes)
	if err != nil {
		t.Error(err)
	}

	// decrypt the ciphertext
	decryptedMsg, err := sn.IBEDecrypt(ciphertextUnmarshalled, id, sigBytes)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted message '%s'\n", string(decryptedMsg))
}
