// It connects to the peer specified by -peer.
// It accepts connections from peers and receives messages from them.
// When it sees a peer with an address it hasn't seen before, it makes a
// connection to that peer.
// It adds an ID field containing a random string to each outgoing message.
// When it recevies a message with an ID it hasn't seen before, it broadcasts
// that message to all connected peers.
//
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"sync"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/campoy/whispering-gophers/util"
	"io"
	"strings"
)

var (
	listenAddr = flag.String("listen", "localhost:8000", "host:port to listen on")
	peerAddr   = flag.String("peer", "", "peer host:port")
	myName     = flag.String("myname", "Anonymous", "myname name")
	aesKey     = flag.String("aeskey", "very-secure-key0", "aeskey key")
	self       string
)

type Message struct {
	ID        string
	Name      string
	Addr      string
	Body      string
	Recipient string
}

func main() {
	flag.Parse()
	aesKeyLen := len(*aesKey)
	if aesKeyLen != 16 && aesKeyLen != 24 && aesKeyLen != 24 {
		log.Println("Current AES key length:", aesKeyLen)
		log.Fatal("Your AES key should be 16, 24 or 32 bytes long.")
	}
	log.Println("Using name:", *myName)
	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	self = l.Addr().String()
	log.Println("Listening on", self)

	if *peerAddr != "" {
		go dial(*peerAddr)
	}
	go readInput()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(c)
	}
}

var peers = &Peers{m: make(map[string]chan<- Message)}

type Peers struct {
	m  map[string]chan<- Message
	mu sync.RWMutex
}

// Add creates and returns a new channel for the given peer address.
// If an address already exists in the registry, it returns nil.
func (p *Peers) Add(addr string) <-chan Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.m[addr]; ok {
		return nil
	}
	ch := make(chan Message)
	p.m[addr] = ch
	return ch
}

// Remove deletes the specified peer from the registry.
func (p *Peers) Remove(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, addr)
}

// List returns a slice of all active peer channels.
func (p *Peers) List() []chan<- Message {
	p.mu.RLock()
	defer p.mu.RUnlock()
	l := make([]chan<- Message, 0, len(p.m))
	for _, ch := range p.m {
		l = append(l, ch)
	}
	return l
}

func broadcast(m Message) {
	for _, ch := range peers.List() {
		select {
		case ch <- m:
		default:
			// Okay to drop messages sometimes.
		}
	}
}

func privateMessage(m Message, peer string) {
	peers.mu.RLock()
	defer peers.mu.RUnlock()
	m.Body = encrypt([]byte(*aesKey), m.Body)
	if _, ok := peers.m[peer]; ok {
		select {
		case peers.m[peer] <- m:
		default:
			// Okay to drop messages sometimes.
		}
	} else {
		broadcast(m)
	}

}

func getPrivateMessageRecipient(msg string) (string, bool) {
	msgParse := strings.SplitN(msg, "|", 2)
	if len(msgParse) > 1 {
		return msgParse[0], true
	} else {
		return "", false
	}
}
func serve(c net.Conn) {
	defer c.Close()
	d := json.NewDecoder(c)
	for {
		var m Message
		err := d.Decode(&m)
		if err != nil {
			log.Println(err)
			return
		}
		if strings.Contains(m.Body, "Spam") {
			continue
		}
		if Seen(m.ID) {
			continue
		}
		if m.Recipient != "" {
			if m.Recipient == self {
				m.Body = decrypt([]byte(*aesKey), m.Body)
				log.Println("Incoming private connection from:", m.Name, m.Addr)
				fmt.Printf("%#v\n", m)
			} else {
				broadcast(m)
			}
		} else {
			log.Println("Incoming connection from:", m.Name, m.Addr)
			fmt.Printf("%#v\n", m)
			broadcast(m)
		}
		go dial(m.Addr)
	}
}

func readInput() {
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		peer, ok := getPrivateMessageRecipient(s.Text())
		m := Message{}
		if ok {
			m = Message{
				ID:        util.RandomID(),
				Name:      *myName,
				Addr:      self,
				Body:      strings.Replace(s.Text(), peer+"|", "", 2),
				Recipient: peer,
			}
			privateMessage(m, peer)
		} else {
			m = Message{
				ID:   util.RandomID(),
				Name: *myName,
				Addr: self,
				Body: s.Text(),
			}
			broadcast(m)
		}
		Seen(m.ID)
	}
	if err := s.Err(); err != nil {
		log.Fatal(err)
	}
}

func dial(addr string) {
	if addr == self {
		return // Don't try to dial self.
	}

	ch := peers.Add(addr)
	if ch == nil {
		return // Peer already connected.
	}
	defer peers.Remove(addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println(addr, err)
		return
	}
	log.Println("Connected to", addr)
	defer c.Close()

	e := json.NewEncoder(c)
	for m := range ch {
		err := e.Encode(m)
		if err != nil {
			log.Println(addr, err)
			return
		}
	}
}

var seenIDs = SeenMessages{sm: make(map[string]bool)}

type SeenMessages struct {
	sm map[string]bool
	mu sync.RWMutex
}

// Seen returns true if the specified id has been seen before.
// If not, it returns false and marks the given id as "seen".
func Seen(id string) bool {
	seenIDs.mu.RLock()
	defer seenIDs.mu.RUnlock()
	if _, ok := seenIDs.sm[id]; ok {
		return true
	}
	seenIDs.sm[id] = true
	return false
}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		log.Println("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}
