// Skeleton to part 9 of the Whispering Gophers code lab.
//
// This program extends part 8.
//
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
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/campoy/whispering-gophers/util"
	"strings"
)

var (
	peerAddr = flag.String("peer", "", "peer host:port")
	myname   = flag.String("myname", "", "myname name")
	self     string
)

type Message struct {
	// TODO: add ID field
	ID   string
	Name string
	Addr string
	Body string
}

func main() {
	flag.Parse()

	l, err := util.Listen()
	if err != nil {
		log.Fatal(err)
	}
	self = l.Addr().String()
	log.Println("Listening on", self)

	go dial(*peerAddr)
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

		// TODO: If this message has seen before, ignore it.
		if strings.Contains(m.Body, "Spam") {
			continue
		}
		if _, ok := seenmsgs.mm[m.ID]; ok {
			continue
		}
		fmt.Printf("%#v\n", m)
		broadcast(m)
		go dial(m.Addr)
	}
}

func readInput() {
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		m := Message{
			// TODO: use util.RandomID to populate the ID field.
			ID:   util.RandomID(),
			Name: *myname,
			Addr: self,
			Body: s.Text(),
		}
		// TODO: Mark the message ID as seen.
		Seen(m.ID)
		bodyParse := strings.SplitN(m.Body, "|", 2)
		if len(bodyParse) > 1 {
			m.Body = bodyParse[1]
			if _, ok := peers.m[bodyParse[0]]; ok {
				peers.m[bodyParse[0]] <- m
			}
		} else {
			broadcast(m)
		}

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

var seenmsgs = SeenMessages{mm: make(map[string]bool)}

// TODO: Create a new map of seen message IDs and a mutex to protect it.
type SeenMessages struct {
	mm map[string]bool
	mu sync.RWMutex
}

// Seen returns true if the specified id has been seen before.
// If not, it returns false and marks the given id as "seen".
func Seen(id string) bool {
	// TODO: Get a write lock on the seen message IDs map and unlock it at before returning.
	seenmsgs.mu.RLock()
	defer seenmsgs.mu.RUnlock()
	// TODO: Check if the id has been seen before and return that later.
	if _, ok := seenmsgs.mm[id]; ok {
		return true
	}
	// TODO: Mark the ID as seen in the map.
	seenmsgs.mm[id] = true
	return false
}
