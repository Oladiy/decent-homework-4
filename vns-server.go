package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	shell "github.com/ipfs/go-ipfs-api"
	"io/ioutil"
	"os"
	"strings"
)

const (
	storageFileName = "storage.txt"
	urlIPFS = "localhost:5001"
)

type Options struct {
	requestType string
	uid string
	ipfsLink string
	sig string
}

func main() {
	options, err := getOptions(new(Options))
	if err != nil {
		fmt.Println(err)
		return
	}

	if options.requestType == "name-record-get" {
		if err = get(options); err != nil {
			fmt.Println(err)
		}
	}

	if options.requestType == "name-record-set" {
		err = set(options)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("result: ok (signature correct)")
		}
	}
}

func get(options *Options) error {
	// Открываем хранилище
	storage, err := os.Open(storageFileName)
	if err != nil {
		return err
	}

	// Получаем IPFS-link по UID
	ipfsLink, err := findIPFSLinkByUID(storage, options.uid)
	if err != nil {
		return err
	}
	fmt.Println("\nlink:", ipfsLink)
	err = storage.Close()
	if err != nil {
		return err
	}

	// Выводим содержимое по IPFS link
	sh := shell.NewShell(urlIPFS)
	infoReader, err := sh.Cat(ipfsLink)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(infoReader)
	if err != nil {
		return err
	}

	fmt.Println(buf.String())

	return infoReader.Close()
}

func findIPFSLinkByUID(storage *os.File, uid string) (string, error) {
	scanner := bufio.NewScanner(storage)
	var containsUID bool
	var line string
	for scanner.Scan() {
		line = scanner.Text()

		if strings.Contains(line, uid + "\t") {
			containsUID = true
			break
		}
	}

	var ipfsLink string
	if containsUID {
		ipfsLinkBoundary := strings.Index(line, "\t") + 1
		ipfsLink = line[ipfsLinkBoundary:]
	} else {
		return ipfsLink, errors.New("there is no such uid in storage")
	}

	return ipfsLink, nil
}

func set(options *Options) error {
	// Извлекаем публичный ключ из uid.
	pubKeyBoundary := strings.Index(options.uid, ":") + 1

	decodedPubKey, _ := hex.DecodeString(options.uid[pubKeyBoundary:])
	publicKey, err := x509.ParsePKIXPublicKey(decodedPubKey)
	if err != nil {
		return err
	}

	// Извлекаем из параметров командной строки ipfsLink и sig и приводим к байтам.
	ipfsLink := []byte(options.ipfsLink)
	sig, _ := hex.DecodeString(options.sig)

	// Проверяем подпись
	if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), ipfsLink, sig) {
		return errors.New("failed to verify data")
	}

	// Проверяем, существует ли файл хранилища. Если нет - создаем.
	var storage *os.File

	_, err = os.Stat(storageFileName)
	if os.IsNotExist(err) {
		storage, err = os.Create(storageFileName)
		if err != nil {
			return err
		}
	} else {
		storage, err = os.Open(storageFileName)
		if err != nil {
			return err
		}
	}

	// Ищем, есть ли уже в хранилище такой uid
	containsUID, lineIndex := findLineIndexByUID(storage, options.uid, pubKeyBoundary)
	if err = storage.Close(); err != nil {
		return err
	}

	// Если uid уже есть - удаляем строку из хранилища.
	if containsUID {
		if err = deleteDeprecatedInfo(lineIndex); err != nil {
			return err
		}
	}

	// Добавляем в хранилище актуальную информацию uid + ipfs link
	if err = updateStorage(options, pubKeyBoundary); err != nil {
		return err
	}

	return nil
}

func findLineIndexByUID(storage *os.File, uid string, pubKeyBoundary int) (bool, int) {
	scanner := bufio.NewScanner(storage)
	var containsUID bool
	var line string
	var lineIndex int
	for scanner.Scan() {
		line = scanner.Text()
		decodedPubKey, _ := hex.DecodeString(line[pubKeyBoundary:])

		if strings.Contains(line[:pubKeyBoundary] + fmt.Sprintf("%x", decodedPubKey), uid) {
			containsUID = true
			break
		}
		lineIndex++
	}

	return containsUID, lineIndex + 1
}

func deleteDeprecatedInfo(lineIndex int) error {
	var err error
	var storage *os.File
	if storage, err = os.OpenFile(storageFileName, os.O_RDWR, 0); err != nil {
		return err
	}

	var storageDataBytes []byte
	if storageDataBytes, err = ioutil.ReadAll(storage); err != nil {
		return err
	}

	n := 1
	deletedLine := skipLines(storageDataBytes, lineIndex - 1)
	tail := skipLines(deletedLine, n)
	truncatedSize := int64(len(storageDataBytes) - len(deletedLine))
	if err = storage.Truncate(truncatedSize); err != nil {
		return err
	}
	if len(tail) > 0 {
		_, err = storage.WriteAt(tail, truncatedSize)
	}

	return storage.Close()
}

func skipLines(storageDataBytes []byte, lineIndex int) []byte {
	for ; lineIndex > 0; lineIndex-- {
		if len(storageDataBytes) == 0 {
			return nil
		}
		indexByte := bytes.IndexByte(storageDataBytes, '\n')
		if indexByte < 0 {
			indexByte = len(storageDataBytes)
		} else {
			indexByte++
		}
		storageDataBytes = storageDataBytes[indexByte:]
	}
	return storageDataBytes
}

func updateStorage(options *Options, pubKeyBoundary int) error {
	outputStream, err := os.OpenFile(storageFileName, os.O_WRONLY | os.O_APPEND, os.ModeAppend)
	if err != nil {
		return err
	}

	// Декодируем публичный ключ в hex-формат
	pubKeyDecoded, err := hex.DecodeString(options.uid[pubKeyBoundary:])
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(outputStream)
	_, err = writer.WriteString(options.uid[:pubKeyBoundary] +
								fmt.Sprintf("%x", pubKeyDecoded) +
								"\t" + options.ipfsLink + "\n")
	err = writer.Flush()
	if err != nil {
		return err
	}
	return outputStream.Close()
}

func getOptions(options *Options) (*Options, error) {
	flag.StringVar(&options.requestType, "request-type", "", "request type")
	flag.StringVar(&options.uid, "uid", "", "<username>:<pub_key>")
	flag.StringVar(&options.ipfsLink, "ipfs-link", "", "IPFS link")
	flag.StringVar(&options.sig, "sig", "", "request type")

	flag.Parse()
	if err := checkGivenOptions(options); err != nil {
		return nil, errors.New("failed to parse flags")
	}

	return options, nil
}

func checkGivenOptions(options *Options) error {
	if options.requestType == "name-record-get" && (len(options.ipfsLink) != 0 || len(options.sig) != 0) {
		return errors.New("use ipfs-link and sig only if request type is name-record-set")
	}
	return nil
}
