package main

import (
	"os"
	"os/exec"
	"log"
	"syscall"
	"fmt"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"errors"
	"flag"
)

var E_MEMLOCK = errors.New("failed to lock memory:\nTry executing with --no-mlock or set capability with: setcap cap_ipc_lock=+ep /path/to/vault-agent")

func main() {
	var file *os.File
	log.SetOutput(os.Stderr)
	// Fork
	if os.Getppid() != 1 {
		// I am the parent
		binary, err := exec.LookPath(os.Args[0])
		if err != nil {
			log.Fatalln(err)
		}
		_, err = os.StartProcess(binary, os.Args, &os.ProcAttr{Dir: "", Env: nil,
			Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}, Sys: nil})
		if err != nil {
			log.Fatalln(err)
		}
		os.Exit(0)
	}

	// I am the child
	noMlockall := flag.Bool("no-mlockall", false, "Disable mlockall syscall usage. Security will be decreased!")

	flag.Parse()

	if !*noMlockall {
		// Lock memory pages in child, too
		err := syscall.Mlockall(syscall.MCL_FUTURE | syscall.MCL_CURRENT)
		if err != nil {
			log.Fatalln(E_MEMLOCK)
		}
	} else {
		log.Println("mlockall syscal usage disabled!")
	}

	// Get new session to disassociate from parent
	_, err := syscall.Setsid()
	if err != nil {
		log.Fatalln(err)
	}
	file, err = os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	// daemon business logic starts here

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	sockPath := fmt.Sprintf("/tmp/vault-agent_%d.sock", os.Geteuid())
	ag, err := newAgent(vaultAddr, vaultToken)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Fprintf(os.Stderr, "[%d] Starting agent at '%s'\n", os.Getpid(), sockPath)
	fmt.Printf("export SSH_AUTH_SOCK=%s\n", sockPath)
	fmt.Printf("export SSH_AGENT_PID=%d\n", os.Getpid())

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalln(err)
	}

	syscall.Dup2(int(file.Fd()), int(os.Stderr.Fd()))
	syscall.Dup2(int(file.Fd()), int(os.Stdout.Fd()))
	syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))

	for {
		conn, err := l.Accept()
		if err != nil {
			// handle error
			continue
		}
		go agent.ServeAgent(&ag, conn)
	}

}
