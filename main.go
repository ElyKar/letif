package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	in      string
	out     string
	decrypt bool
)

var rootCmd = &cobra.Command{
	Use:   "letif -in input [-d] [-out output]",
	Short: "letif is a command-line tool to encrypt and decrypt a file using AES-256",
	Long: `letif is a command-line tool to encrypt and decrypt a file using AES-256.
If the passphrase is more than 32-bytes long, it will be truncated to 32.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if in == "" {
			cmd.Usage()
			os.Exit(1)
		}

		inData, err := ioutil.ReadFile(in)
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		}

		var passphrase string
		err = readPassword(&passphrase, !decrypt)
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		}

		var outData []byte
		var function processFunc

		if decrypt {
			if out == "" {
				out = "letif.out"
			}
			function = decryptAES
		} else {
			if out == "" {
				out = in + ".ltf"
			}
			function = encryptAES
		}

		outData, err = function(passphrase, inData)
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		}

		if fileExists(out) {
			fmt.Println("Something went wrong: ", fmt.Errorf("File exists '%s'", out))
			os.Exit(1)
		}

		err = ioutil.WriteFile(out, outData, os.ModePerm)
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		}

		_ = os.Remove(in)

	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&in, "input", "i", "", "Input file")
	rootCmd.PersistentFlags().StringVarP(&out, "output", "o", "", "Output file")
	rootCmd.PersistentFlags().BoolVarP(&decrypt, "decrypt", "d", false, "Set to decrypt in to out, unset to encrypt in to out")
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("An error occurred ", err.Error())
		os.Exit(1)
	}

}

type processFunc func(string, []byte) ([]byte, error)

func encryptAES(key string, data []byte) ([]byte, error) {
	key = extendKey(key)
	block, err := aes.NewCipher(bytes.NewBufferString(key).Bytes())
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(data)
	ciphertext := make([]byte, aes.BlockSize+len(b))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decryptAES(key string, data []byte) ([]byte, error) {
	key = extendKey(key)
	block, err := aes.NewCipher(bytes.NewBufferString(key).Bytes())
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("Ciphertext is not correctly encrypted")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func readPassword(ptr *string, needConfirm bool) error {

	if !terminal.IsTerminal(0) {
		fmt.Println("Warning: on a non-UNIX terminal your password will be visible")
	}

	oldState, err := terminal.MakeRaw(0)
	defer terminal.Restore(0, oldState)

	if err != nil {
		return err
	}

	fmt.Print("Enter your passphrase: ")
	passphrase, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return err
	}

	if needConfirm {
		fmt.Print("Confirm your passphrase: ")
		confirm, err := terminal.ReadPassword(0)
		fmt.Println()
		if err != nil {
			return err
		}

		if len(passphrase) == 0 {
			return errors.New("Password can't be empty")
		}

		if fmt.Sprintf("%s", passphrase) != fmt.Sprintf("%s", confirm) {
			return errors.New("Password do not match")
		}
	}

	*ptr = fmt.Sprintf("%s", passphrase)

	return nil
}

// AES-256 requires a 32 bytes key, this function extend the key to this length
func extendKey(key string) string {
	key = strings.Repeat(key, 32/len(key)+1)
	return key[:32]
}
