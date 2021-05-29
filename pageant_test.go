// +build windows

package pageant_test

import (
	"flag"
	"strings"
	"testing"

	"github.com/davidmz/go-pageant"
	"golang.org/x/crypto/ssh"
)

// 1. Pageant must be started in system
// 2. At least one ssh-rsa key must be loaded to pageant
// 3. Test must be started as `go test -ssh-user username -ssh-host host(:port)`,
//    where host(:port) and username is the valid ssh credentials that matches
//    with the ssh-rsa key in pageant.

var (
	sshUser string
	sshHost string
)

func init() {
	flag.StringVar(&sshUser, "ssh-user", "", "ssh user name")
	flag.StringVar(&sshHost, "ssh-host", "", "ssh host(:port) name")
}

func TestAvailability(t *testing.T) {
	ok := pageant.Available()
	if !ok {
		t.Fatal("pageant is not available")
	}
}

func TestAgentKeys(t *testing.T) {
	agent := pageant.New()
	signers, err := agent.Signers()
	if err != nil {
		t.Fatalf("error getting signers: %v", err)
	}
	if len(signers) == 0 {
		t.Fatal("no signers found in agent")
	}
	if signers[0].PublicKey().Type() != "ssh-rsa" {
		t.Fatalf("unexpected signer key type: %v (expected: ssh-rsa)", signers[0].PublicKey().Type())
	}
}

func TestSSHConnection(t *testing.T) {
	if sshUser == "" || sshHost == "" {
		t.Fatal("-ssh-user and/or -ssh-host command-line flags are not specified")
	}

	if !strings.Contains(sshHost, ":") {
		sshHost += ":22"
	}

	signers, err := pageant.New().Signers()
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
