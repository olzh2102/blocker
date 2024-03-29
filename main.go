package main

import (
	"context"
	"log"

	"github.com/olzh2102/blocker/node"
	"github.com/olzh2102/blocker/proto"
	"google.golang.org/grpc"
)

func main() {
	makeNode(":3000", []string{})
	makeNode(":4000", []string{":3000"})

	// go func() {
	// 	for {
	// 		time.Sleep(time.Second * 2)
	// 		makeTransaction()
	// 	}
	// }()

	select {}
}

func makeNode(listenAddr string, bootstapNodes []string) *node.Node {
	n := node.NewNode()
	go n.Start(listenAddr)
	if len(bootstapNodes) > 0 {
		if err := n.BootstrapNetwork(bootstapNodes); err != nil {
			log.Fatal(err)
		}
	}
	return n
}

func makeTransaction() {
	client, err := grpc.Dial(":3000", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	c := proto.NewNodeClient(client)

	version := &proto.Version{
		Version:    "blocker-0.1",
		Height:     1,
		ListenAddr: ":4000",
	}

	_, err = c.Handshake(context.TODO(), version)
	if err != nil {
		log.Fatal(err)
	}
}
