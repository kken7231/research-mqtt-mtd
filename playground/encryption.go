package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
)

// Encryption function
func encryptAESGCM(plaintext, key, iv []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES GCM mode: %w", err)
	}

	ciphertext = aesGCM.Seal(nil, iv, plaintext, nil)
	tag = ciphertext[len(ciphertext)-aesGCM.Overhead():]        // Extract the tag from the end
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()] // Remove the tag from ciphertext

	return ciphertext, tag, nil
}

// Decryption function
func decryptAESGCM(ciphertext, key, iv, tag []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES GCM mode: %w", err)
	}

	ciphertextWithTag := append(ciphertext, tag...) // Append the tag back to the ciphertext
	plaintext, err = aesGCM.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func main() {
	key, _ := hex.DecodeString("3974BC08993A24BFED9F24D189936095") // 128-bit key (16 bytes)
	iv, _ := hex.DecodeString("000000000001e24000000000")          // 12-byte IV for GCM
	plaintext := []byte("hello, world")                            // Example plaintext

	fmt.Printf("Key (hex): %s\n", hex.EncodeToString(key))
	fmt.Printf("IV (hex): %s\n", hex.EncodeToString(iv))
	fmt.Printf("Plaintext (hex): %s\n", hex.EncodeToString(plaintext))

	// Encrypt the plaintext
	ciphertext, tag, err := encryptAESGCM(plaintext, key, iv)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Ciphertext (hex): %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("Tag (hex): %s\n", hex.EncodeToString(tag))

	// Decrypt the ciphertext
	decryptedText, err := decryptAESGCM(ciphertext, key, iv, tag)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted Text: %s\n", string(decryptedText))
}
