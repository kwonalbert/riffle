import sys
import os
import threading
import time

m = int(sys.argv[1])
n = int(sys.argv[2])
mode = sys.argv[3]
file_dir = sys.argv[4]

gopath = os.environ['GOPATH']

server_cmd = "%s/bin/server -i %d -n %d -s %s/src/github.com/kwonalbert/riffle/servers -m %s -p1 %d"
command = "%s/bin/client -i %d -s %s/src/github.com/kwonalbert/riffle/servers -m %s -w %s -f %s"

server_file = open('%s/src/github.com/kwonalbert/riffle/servers' % gopath, 'w')
for i in range(m):
    server_file.write('localhost:' + str(8000+i) + '\n')
server_file.close()

def spawn(c):
    os.system(c)

ss = []
for i in range(m):
    c = server_cmd % (gopath, i, n, gopath, mode, 8000 + i)
    t = threading.Thread(target=spawn, args=(c,))
    ss.append(t)
    t.start()

time.sleep(2)

ts = []
for i in range(0, n):
    c = command % (gopath, i%m, gopath, mode, file_dir + '/file' + str(i) + '.torrent', file_dir + '/file' + str(i))
    t = threading.Thread(target=spawn, args=(c,))
    ts.append(t)
    t.start()

for t in ts:
    t.join()

os.system('killall -9 server')
os.system('killall -9 client')
