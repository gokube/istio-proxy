package main

import (
        "fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/spf13/cobra"

        pb "localtest/grpctest/authz/authz_v1"
)

type authzServer struct {
	c	int
}

const (
	dikastesSockFile string = "/tmp/dikastes/server.sock"
)

var (
	resp_error int = 0
	CfgListen  string
	CfgUds	   bool
	CfgUdsFile string
	RootCmd = &cobra.Command{
		Use: "authzRpcServer",
	        Short: "Test Authz Envoy client",
		Long: "Test Authz Envoy client",
	}
)

func init() {
	RootCmd.PersistentFlags().StringVarP(&CfgListen, "listen", "l", "localhost:9091", "ListenSocket")
	RootCmd.PersistentFlags().BoolVarP(&CfgUds, "uds", "u", true, "Use Unix Domain Socket")
	RootCmd.PersistentFlags().StringVarP(&CfgUdsFile, "sock", "s", dikastesSockFile, "Unix domain socket file")
}

func (s *authzServer) Check(ctx context.Context, request *pb.Request) (*pb.Response, error) {
	var r string
	var e bool
        r = "permit"
        e = true
	if s.c % 2 != 0 && resp_error == 1 {
		r = "deny"
		e = false
	}
	log.Printf("%v Check called for %v, resp: %v", s.c, request, r)
	resp := fmt.Sprintf("all good %v", s.c)
	s.c += 1
	if e == false {
		status := &pb.Response_Status{Code: pb.Response_Status_PERMISSION_DENIED, Message: resp }
		return &pb.Response{Status: status}, nil
        }
	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: resp}
	return &pb.Response{Status: status}, nil
}

func newServer() *authzServer {
	s := new(authzServer)
	return s
}

func main() {
        if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, newServer())

	var lis net.Listener
	var err error
	if CfgUds == false {
		lis, err = net.Listen("tcp", CfgListen)
		if err != nil {
			log.Fatalf("failed to %v", err)
		}
	} else {
                _, e := os.Stat(CfgUdsFile)
                if e == nil {
                  e := os.RemoveAll(CfgUdsFile)
                  if e != nil {
	              log.Fatalf("failed to %v %v", CfgUdsFile, err)
                  }
                }
		lis, err = net.Listen("unix", CfgUdsFile)
		if err != nil {
			log.Fatalf("failed to %v", err)
		}
	}


	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(ln net.Listener, c chan os.Signal) {
		<-c
		ln.Close()
		os.Exit(0)
	}(lis, sigc)

	grpcServer.Serve(lis)
}
