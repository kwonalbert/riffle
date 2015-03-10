package afs

import (
	"fmt"
	"log"
	"sync"

	. "afs/server"
	. "afs/client"
	. "afs/lib"
)

func setup(numServers int, numClients int) ([]*Server, []*Client) {
	fmt.Println(fmt.Sprintf("Setting up for %d servers and %d clients", numServers, numClients))
	ss := make([]string, numServers)
	cs := make([]string, numClients)
	for i := range ss {
		ss[i] = fmt.Sprintf("127.0.0.1:%d", 8000+i)
	}
	for i := range cs {
		cs[i] = fmt.Sprintf("127.0.0.1:%d", 9000+i)
	}

	servers := make([]*Server, numServers)
	clients := make([]*Client, numClients)

	fmt.Println("Starting servers")
	var wg sync.WaitGroup
	for i := range ss {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := NewServer(ss[i], 8000+i, i, ss)
			servers[i] = s
			s.MainLoop()
		}(i)
	}
	wg.Wait()

	for _, s := range servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			s.ConnectServers()
		}(s)
	}
	wg.Wait()

	fmt.Println("Registering Clients")
	for i := range cs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := NewClient(fmt.Sprintf("127.0.0.1:%d", 9000+i), ss, "127.0.0.1:8000")
			clients[i] = c
			c.Register(0)
		} (i)
	}
	wg.Wait()

	for _, c := range clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			c.RegisterDone()
		} (c)
	}
	wg.Wait()

	fmt.Println("Done Registration")

	return servers, clients
}

func compareSecrets(secerets1 [][]byte, secerets2 [][]byte) {
	for i := range secerets1 {
		for j := range secerets1[i] {
			if secerets1[i][j] != secerets2[i][j] {
				fmt.Println(secerets1)
				fmt.Println(secerets2)
				panic("Sharing secrets didn't work!")
			}
		}
	}
}

func registerBlocks(testData [][]byte) {
	for i, c := range clients {
		c.RegisterBlock(testData[i])
	}

}

func request(testData [][]byte, offset int) {
	n := len(clients)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(i int, c *Client) {
			defer wg.Done()
			c.RequestBlock(i, Suite.Hash().Sum(testData[(i+offset)%n]))
		} (i, c)
	}
	wg.Wait()
}

func upload() {
	for _, c := range clients {
		go c.Upload()
	}
}

func uploadBlock(testData [][]byte) {
	for i, c := range clients {
		go func(i int, c *Client) {
			upblock := Block {
				Block: testData[i],
				Round: 0,
			}
			c.UploadBlock(upblock)
		} (i, c)
	}
}

func download(testData [][]byte) {
	//upload blocks
	res := make([][]byte, NumClients)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(i int, c *Client) {
			defer wg.Done()
			res[i] = c.Download()
		} (i, c)
	}
	wg.Wait()

	found := make([]bool, NumClients)
	for i := range found {
		found[i] = false
	}

	for i := range testData {
		found[i] = false
		for j := range res {
			same := true
			same = same && (len(res[j]) == len(testData[i]))
			for k := range res[j] {
				same = same && (testData[i][k] == res[j][k])
			}
			if same {
				found[i] = true
				break
			}
		}
		if !found[i] {
			log.Fatal("Didn't get all the data back")
		}
	}
}

func downloadBlock(testData [][]byte) {
	//upload blocks
	res := make([][]byte, NumClients)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(i int, c *Client) {
			defer wg.Done()
			res[i] = c.DownloadBlock(Suite.Hash().Sum(testData[i]))
		} (i, c)
	}
	wg.Wait()

	found := make([]bool, NumClients)
	for i := range found {
		found[i] = false
	}

	for i := range testData {
		found[i] = false
		for j := range res {
			same := true
			same = same && (len(res[j]) == len(testData[i]))
			for k := range res[j] {
				same = same && (testData[i][k] == res[j][k])
			}
			if same {
				found[i] = true
				break
			}
		}
		if !found[i] {
			log.Fatal("Didn't get all the data back")
		}
	}
}

func membership(res []byte, set [][]byte) {
	for i := range set {
		same := true
		same = same && (len(res) == len(set[i]))
		for k := range res {
			same = same && (set[i][k] == res[k])
		}
		if same {
			return
		}
	}
	fmt.Println("res: ", res)
	log.Fatal("Didn't get all data back")
}
