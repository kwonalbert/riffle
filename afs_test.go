package afs

import (
	"crypto/rand"
	//"fmt"
	//"log"
	"os"
	"runtime"
	"sync"
	"time"

	"testing"

	"afs/server"
	"afs/client"
	"afs/lib"

	"github.com/dedis/crypto/edwards"
)

var servers []*server.Server = nil
var clients []*client.Client = nil

var ServerAddrs []string = []string{"127.0.0.1:8000", "127.0.0.1:8001"}
var Suite = edwards.NewAES128SHA256Ed25519(false)
const NumClients = 3
const NumServers = 2

func TestSetup(t *testing.T) {
	//nothing goes on here
}

func TestFileShare(t *testing.T) {
	for s := range servers {
		servers[s].FSMode = true
	}
	for c := range clients {
		clients[c].FSMode = true
	}
	b := 10

	testData := make([][][]byte, b)
	wantedArr := make([][][]byte, b)
	for i := 0; i < b; i++ {
		testData[i] = make([][]byte, NumClients)
		wantedArr[i] = make([][]byte, NumClients)
		for j := range testData[i] {
			data := make([]byte, lib.BlockSize)
			rand.Read(data)
			//data[j] = 1
			// if i == 0 {
			// 	fmt.Println("block:", data)
			// }
			testData[i][j] = data
			h := Suite.Hash()
			h.Write(data)
			wantedArr[i][j] = h.Sum(nil)
		}
		registerBlocks(testData[i])
	}

	var clientWg sync.WaitGroup
	for c := range clients {
		clientWg.Add(1)
		go func(c int) { //a client
			defer clientWg.Done()
			var wg sync.WaitGroup
			var r uint64 = 0
			for ; r < lib.MaxRounds; r++ {
				wg.Add(1)
				go func (c int, r uint64) {
					defer wg.Done()
					for ; r < uint64(len(wantedArr)); {
						client := clients[c]
						hash, hashes := client.RequestBlock(wantedArr[r][c], r)
						hashes = client.Upload(hashes, r)
						block := client.Download(hash, hashes, r)
						lib.Membership(block, testData[r])
						r += lib.MaxRounds
					}
				} (c, r)
			}
			wg.Wait()
		} (c)
	}
	clientWg.Wait()
}

func TestMicroblog(t *testing.T) {
	for s := range servers {
		servers[s].FSMode = false
	}
	for c := range clients {
		clients[c].FSMode = false
	}
	b := 10

	testData := make([][][]byte, b)
	for i := 0; i < b; i++ {
		testData[i] = make([][]byte, NumClients)
		for j := range testData[i] {
			data := make([]byte, lib.BlockSize)
			rand.Read(data)
			//data[j] = 1
			// if i == 0 {
			// 	fmt.Println("block:", data)
			// }
			testData[i][j] = data
		}
	}

	var clientWg sync.WaitGroup
	for c := range clients {
		clientWg.Add(1)
		go func(c int) { //a client
			defer clientWg.Done()
			var wg sync.WaitGroup
			var r uint64 = 0
			for ; r < lib.MaxRounds; r++ {
				wg.Add(1)
				go func (c int, r uint64) {
					defer wg.Done()
					for ; r < lib.MaxRounds*3; {
						client := clients[c]
						block := make([]byte, lib.BlockSize)
						rand.Read(block)
						client.UploadSmall(lib.Block{Block: block, Round: r, Id: client.Id()})
						client.DownloadAll(r)
						r += lib.MaxRounds
					}
				} (c, r)
			}
			wg.Wait()
		} (c)
	}
	clientWg.Wait()
}

func TestMain(m *testing.M) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	servers, clients = setup(NumServers, NumClients)
	time.Sleep(1000 * time.Millisecond)

	os.Exit(m.Run())
}
