package main

import (
	"bytes"
	"fmt"
	"os"

	"file-encrypt.com/filecrypt"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}
	function := os.Args[1]
	// 调用相应的函数
	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run encrypt to encrypt a file,and decrypt to decrypt")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for you day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("\tgo run .encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}

func encryptHandle() {
	if len(os.Args) < 3 {
		println("missing the path to the file. For more info, run go run . help")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		panic("file does not exist")
	}
	password := getPassword()
	fmt.Println("\nEncrypting...")
	filecrypt.Encrypt(file, password)
	fmt.Println("\n file sucessfully protected")

}

func decryptHandle() {
	if len(os.Args) < 3 {
		println("missing the path to the file. For more info, run go run . help")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		panic("file does not exist")
	}
	fmt.Print("Enter password:")
	password, _ := term.ReadPassword(0)
	fmt.Println("\nDecrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("\n file sucessfully decrypted")

}

func getPassword() []byte {
	fmt.Print("Enter password")
	password, _ := term.ReadPassword(0)
	fmt.Print("\nConfim Password: ")
	password2, _ := term.ReadPassword(0)
	if !validatePassword(password, password2) {
		//panic("passwords do not match")
		fmt.Print("\nPassword do not match. please try again\n ")
		return getPassword()

	}
	return password

}

func validatePassword(password1, password2 []byte) bool {
	if !bytes.Equal(password1, password2) {
		return false
	}
	return true
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
