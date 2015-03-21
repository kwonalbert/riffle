import sys
import os
import threading
import time

node_num = int(sys.argv[1])
m = int(sys.argv[2])
n = int(sys.argv[3])

per_node = 0
if n % node_num == 0:
    per_node = n/node_num
else:
    per_node = n/node_num + 1

server_cmd = "/users/kwonal/workspace/gos/bin/server -i %d -n %d -s /users/kwonal/workspace/gos/src/afs/servers -cpuprofile prof%d"
command = "zsh /users/kwonal/workspace/gos/src/afs/spawn_clients.sh %d %d %d %d"


def spawn(node, c):
    os.system('ssh %s "%s"' % (node, c))

ss = []
for i in range(m):
    c = server_cmd % (i, n, i)
    t = threading.Thread(target=spawn, args=('server%d' % i, c,))
    ss.append(t)
    t.start()

time.sleep(2)

node = 0

ts = []
for i in range(0, n, per_node):
    c = command % (i, min(i+per_node,n), n, node % m)
    t = threading.Thread(target=spawn, args=('node%d' % node, c,))
    ts.append(t)
    t.start()
    #print i, n, per_node, node
    node += 1

for t in ts:
    t.join()

ts = []
for i in range(m):
    c = "killall server"
    t = threading.Thread(target=spawn, args=('server%d' % i, c,))
    ts.append(t)
    t.start()
