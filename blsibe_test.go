package blsibe

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/drand/kyber/util/random"
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

	msg := []byte("The quick brown fox jumps over the lazy dog, and then some purple unicorns appear!")
	id := []byte("{policy: True}")

	// symmetric encrypt the message
	key := [32]byte{}
	random.Bytes(key[:], random.New())

	encryptedMsg, err := SymmetricEncrypt(msg, key)
	if err != nil {
		t.Error(err)
	}

	encryptedSymmetricKey, err := sn.IBEEncrypt(key[:], id)
	if err != nil {
		t.Error(err)
	}

	encryptedSymmetricKeyBytes, err := CiphertextToBytes(sn.Suite, encryptedSymmetricKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("cipherText:", base64.StdEncoding.EncodeToString(encryptedSymmetricKeyBytes))
	fmt.Println("encryptedMsg:", base64.StdEncoding.EncodeToString(encryptedMsg.Box))

	// material required for decryption: key, encryptedMsg (box + nonce), id, encryptedSymmetricKeyBytes

	// TODO: marshal Box from encryptedMsg

	// #############################################

	// TODO in prod: eval the policy on each signer.....

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

	encryptedSymmetricKeyUnmarshalled, err := BytesToCiphertext(sn.Suite, encryptedSymmetricKeyBytes)
	if err != nil {
		t.Error(err)
	}

	// decrypt the symmetric key
	decryptedKey, err := sn.IBEDecrypt(encryptedSymmetricKeyUnmarshalled, id, sigBytes)
	if err != nil {
		t.Error(err)
	}

	// convert decryptedKey to [32]byte
	var decryptedKey32 [32]byte
	copy(decryptedKey32[:], decryptedKey)

	// decrypt the message
	decryptedMsg, err := SymmetricDecrypt(encryptedMsg, decryptedKey32)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted message '%s'\n", string(decryptedMsg))
}

func TestSymmerticEncryptDecrypt(t *testing.T) {
	plaintext := []byte("Hello, BLSIBE!")
	key := [32]byte{}
	random.Bytes(key[:], random.New())

	ciphertext, err := SymmetricEncrypt(plaintext, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("Ciphertext:", base64.StdEncoding.EncodeToString(ciphertext.Box))

	// decrypt the ciphertext
	msg, err := SymmetricDecrypt(ciphertext, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("Decrypted plaintext:", string(msg))

	if string(msg) != string(plaintext) {
		t.Error("Decrypted message does not match the original message")
	}
}
