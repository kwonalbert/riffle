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

serv_name = 'draco%d'
node_name = 'draco%d'
serv_start = 20
node_start = 1

server_cmd = "/afs/csail.mit.edu/u/k/kwonal/workspace/gos/bin/server -i %d -n %d -s /afs/csail.mit.edu/u/k/kwonal/workspace/gos/src/afs/servers -cpuprofile cpuprof%d -memprofile memprof%d -m m"
command = "zsh /afs/csail.mit.edu/u/k/kwonal/workspace/gos/src/afs/spawn_clients.sh %d %d %d %d m"

def spawn(node, c):
    os.system('ssh -p 22 %s "%s"' % (node, c))

ss = []
for i in range(m):
    c = server_cmd % (i, n, i, i)
    t = threading.Thread(target=spawn, args=(serv_name % (serv_start + i), c,))
    ss.append(t)
    t.start()

time.sleep(2)

node = node_start

ts = []
for i in range(0, n, per_node):
    c = command % (i, min(i+per_node,n), n, node % m)
    t = threading.Thread(target=spawn, args=(node_name % node, c,))
    ts.append(t)
    t.start()
    #print i, n, per_node, node
    node += 1

for t in ts:
    t.join()

ts = []
for i in range(m):
    c = "killall -9 server"
    t = threading.Thread(target=spawn, args=(serv_name % (serv_start + i), c,))
    ts.append(t)
    t.start()

for t in ts:
    t.join()

node = node_start
ts = []
for i in range(0, n, per_node):
    c = "killall -9 client"
    t = threading.Thread(target=spawn, args=(node_name % node, c,))
    ts.append(t)
    t.start()
    node += 1

for t in ts:
    t.join()
