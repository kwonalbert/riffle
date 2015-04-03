package afs

import (
	"fmt"
	"log"
	"sync"

	"afs/server"
	"afs/client"
	"afs/lib"
)

func setup(numServers int, numClients int) ([]*server.Server, []*client.Client) {
	fmt.Println(fmt.Sprintf("Setting up for %d servers and %d clients", numServers, numClients))
	server.SetTotalClients(numClients)

	ss := make([]string, numServers)
	cs := make([]string, numClients)
	for i := range ss {
		ss[i] = fmt.Sprintf("127.0.0.1:%d", 8000+i)
	}
	for i := range cs {
		cs[i] = fmt.Sprintf("127.0.0.1:%d", 9000+i)
	}

	servers := make([]*server.Server, numServers)
	clients := make([]*client.Client, numClients)

	fmt.Println("Starting servers")
	var wg sync.WaitGroup
	for i := range ss {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := server.NewServer(ss[i], 8000+i, i, ss, false)
			servers[i] = s
			_ = s.MainLoop(0, nil)
		} (i)
	}
	wg.Wait()

	fmt.Println("Registering Clients")
	for i := range cs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := client.NewClient(ss, ServerAddrs[i%len(ServerAddrs)], false)
			clients[i] = c
			c.Register(0)
			c.RegisterDone(0)
			c.ShareSecret()
			//c.UploadKeys(0)
		} (i)
	}
	wg.Wait()

	fmt.Println("Done Registration")

	for i, s := range servers {
		masks := s.Masks()
		secrets := s.Secrets()
		cmasks := make([][][]byte, lib.MaxRounds)
		csecrets := make([][][]byte, lib.MaxRounds)
		for r := range masks {
			cmasks[r] = make([][]byte, NumClients)
			csecrets[r] = make([][]byte, NumClients)
			for _, c := range clients {
				cmasks[r][c.Id()] = c.Masks()[r][i]
				csecrets[r][c.Id()] = c.Secrets()[r][i]
			}
			compareSecrets(masks[r], cmasks[r])
			compareSecrets(secrets[r], csecrets[r])
		}
	}


	shared := make([][]bool, numClients)
	for i := range shared {
		shared[i] = make([]bool, numServers)
		for j := range shared[i] {
			shared[i][j] = false
		}
	}

	skeyss := make([][][]byte, len(servers))
	for i, s := range servers {
		skeyss[i] = s.Keys()
	}

	for i, c := range clients {
		ckeys := c.Keys()
		for j := range ckeys {
			//server k's key
			if lib.Membership(ckeys[j], skeyss[j]) == -1 {
				log.Fatal("Key share failed!")
			}
			shared[i][j] = true
		}
	}
	for i := range shared {
		for j := range shared[i] {
			if !shared[i][j] {
				fmt.Println("Key duplicated!")
			}
		}
	}

	fmt.Println("Secret shared")

	return servers, clients
}

func compareSecrets(secerets1 [][]byte, secerets2 [][]byte) {
	for i := range secerets1 {
		for j := range secerets1[i] {
			if secerets1[i][j] != secerets2[i][j] {
				fmt.Println(secerets1[i])
				fmt.Println(secerets2[i])
				log.Fatal("Sharing secrets didn't work!", i, j)
			}
		}
	}
}

func registerBlocks(testData [][]byte) {
	for i, c := range clients {
		c.RegisterBlock(testData[i])
	}

}

