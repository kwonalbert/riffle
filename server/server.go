package server

import (
	// "flag"
	// "fmt"
	// "log"
	// "net"
	// "net/rpc"
	// "time"

	. "lib" //types and utils
	. "client"
)

const BufSize = 5

type Server struct {
	addr           string //server addr
	blocks         [][]Block
	reqs           [][][]byte //reqs to this server
	allReqs        [][][]byte //all clients' reqs

	//clients
	clients        []Client //clients connected here
	numClients     int //#clients connect here
	totalClients   int //total number of clients (sum of all servers)

	//uploading
	upsChan        chan Block
	upRound        int

	//requesting
	reqsChan       chan Request
	reqRound       int

	//downloading

}

func NewServer(addr string) *Server {
	s := Server{
		addr:         addr,
		blocks:       nil,
		reqs:         nil,
		allReqs:      nil,

		clients:      nil,
		numClients:   0,
		totalClients: 0,

		//AK: add some buffers here for efficieny?
		upsChan:      make(chan Block),


		reqsChan:     make(chan Request),
	}

	return &s
}

//request a block by uploading hash to this server; rpc call
func (s *Server) ReqBlock(h Request, _ *int) error {
	s.reqsChan <- h
	return nil
}

//TODO: better way to handle multiple rounds of request
//TODO: make sure the a request isn't deleted before it's serviced
func (s *Server) GatherReq() {
	for i := 0; i < s.numClients; i++ {
		req := <-s.reqsChan
		s.reqs[req.Round % BufSize][i] = req.Hash
	}
}

//broadcast all requests to uploaders(clients)
func (s *Server) BroadcastReq() {
	// for i, c := range s.clients {
	// 	//TODO: call rpc to broadcast
	// }
}

//upload a block to this server; rpc call
func (s *Server) UpBlock(b Block, _ *int) error {
	s.upsChan <- b
	return nil
}

//broadcast all available hashes to downloaders(clients)
func (s *Server) BroadcastAvailable() {

}

//download is done through PIR
/*
TODO: Code from PIR part goes here
*/

//setup the clients, and other anonymity servers
//TODO: setup server's arr for blocks,requests,etc based on the num client
func (s *Server) setup() {

}


func (s *Server) serverLoop() {
	for {

	}
}



func main() {

}
