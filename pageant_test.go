//go:build windows

package pageant

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Tests that need Pageant are skipped when it is not running.
// TestSSHConnection also needs `go test -ssh-user username -ssh-host host(:port)`,
// where host(:port) and username are valid ssh credentials matching a key in Pageant.

var (
	sshUser string
	sshHost string
)

func init() {
	flag.StringVar(&sshUser, "ssh-user", "", "ssh user name")
	flag.StringVar(&sshHost, "ssh-host", "", "ssh host(:port) name")
}

func requirePageant(t *testing.T) {
	if !Available() {
		t.Skip("pageant is not running")
	}
}

func TestQueryValidation(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
		err  error
	}{
		{"empty", nil, ErrInvalidMessageFormat},
		{"short", []byte{0, 0}, ErrInvalidMessageFormat},
		{"length mismatch", []byte{0, 0, 0, 5, 11}, ErrInvalidMessageFormat},
		{"too long", make([]byte, MaxMessageLen+1), ErrMessageTooLong},
	}
	for _, c := range cases {
		if _, err := query(c.msg); err != c.err {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
		}
	}
}

func TestConnDropsStaleData(t *testing.T) {
	requirePageant(t)
	c := &conn{buf: []byte("stale")}
	// SSH_AGENTC_REQUEST_IDENTITIES
	if _, err := c.Write([]byte{0, 0, 0, 1, 11}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c.buf, []byte("stale")) {
		t.Fatal("stale data left in buffer")
	}
}

func TestAgentKeys(t *testing.T) {
	requirePageant(t)
	signers, err := New().Signers()
	if err != nil {
		t.Fatalf("error getting signers: %v", err)
	}
	if len(signers) == 0 {
		t.Skip("no keys loaded in pageant")
	}
	data := []byte("go-pageant test")
	for _, s := range signers {
		sig, err := s.Sign(nil, data)
		if err != nil {
			t.Fatalf("%s: sign: %v", s.PublicKey().Type(), err)
		}
		if err := s.PublicKey().Verify(data, sig); err != nil {
			t.Fatalf("%s: verify: %v", s.PublicKey().Type(), err)
		}
	}
}

func TestSSHConnection(t *testing.T) {
	requirePageant(t)
	if sshUser == "" || sshHost == "" {
		t.Skip("-ssh-user and/or -ssh-host command-line flags are not specified")
	}

	if !strings.Contains(sshHost, ":") {
		sshHost += ":22"
	}

	signers, err := New().Signers()
	if err != nil {
		t.Fatalf("error getting signers: %v", err)
	}
	config := ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            sshUser,
	}

	sshConn, err := ssh.Dial("tcp", sshHost, &config)
	if err != nil {
		t.Fatalf("failed to connect to %s@%s: %s", sshUser, sshHost, err)
	}
	sshConn.Close()
}
