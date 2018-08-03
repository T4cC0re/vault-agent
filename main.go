package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"errors"
	"flag"
	"runtime"
)

var E_MEMLOCK = errors.New("failed to lock memory:\nTry executing with --no-mlockall or set capability with: setcap cap_ipc_lock=+ep /path/to/vault-agent")

func main() {
	var file *os.File
	log.SetOutput(os.Stderr)

	noMlockall := flag.Bool("no-mlockall", false, "Disable mlockall syscall usage. Security will be decreased!")
	foreground := flag.Bool("foreground", false, "Run in foreground")
	flag.Parse()

	// Reexec in background
	if os.Getppid() != 1 && !*foreground {
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

	if *noMlockall || runtime.GOOS == "darwin" {
		log.Println("mlockall syscall usage disabled by flag or OS!")
	} else {
		// Lock memory pages in child, too
		err := syscall.Mlockall(syscall.MCL_FUTURE | syscall.MCL_CURRENT)
		if err != nil {
			log.Fatalln(E_MEMLOCK)
		}
	}
	// daemon business logic starts here

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	sockPath := fmt.Sprintf("/tmp/vault-agent_%d.sock", os.Geteuid())
	ag, err := newAgent(vaultAddr, vaultToken, "/vault-agent")
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("[%d] Starting agent at '%s'\n", os.Getpid(), sockPath)
	fmt.Printf("export SSH_AUTH_SOCK=%s\n", sockPath)
	fmt.Printf("export SSH_AGENT_PID=%d\n", os.Getpid())

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalln(err)
	}

	if !*foreground {
		// Get new session to disassociate from parent
		_, err := syscall.Setsid()
		if err != nil {
			log.Fatalln(err)
		}

	func () {
		// Disassociate std{in,out,err}
		file, err = os.OpenFile("/dev/null", os.O_RDWR, 0)
		if err != nil {
			log.Fatalln(err)
		}
		defer file.Close()
		syscall.Dup2(int(file.Fd()), int(os.Stderr.Fd()))
		syscall.Dup2(int(file.Fd()), int(os.Stdout.Fd()))
		syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			// handle error
			continue
		}
		go agent.ServeAgent(ag, conn)
	}

}
