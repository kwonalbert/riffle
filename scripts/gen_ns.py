import sys

m = int(sys.argv[1])
n = int(sys.argv[2])
fn = sys.argv[3]

os = 'UBUNTU12-64-STD'
c_hw = 'pc3000'
s_hw = 'd710'

header = """set ns [new Simulator]
source tb_compat.tcl\n"""

set_node = """set node%d [$ns node]
tb-set-node-os $node%d %s
tb-set-hardware $node%d %s\n"""

set_server = """set server%d [$ns node]
tb-set-node-os $server%d %s
tb-set-hardware $server%d %s\n"""

link = """set link%d [$ns duplex-link $server%d $server%d 1000000kb 0ms DropTail]\n"""

lan = """ set lan%d [$ns make-lan "%s $server%d" 1000000kb 0ms]
tb-set-node-lan-bandwidth $server%d $lan%d 1000000kb\n"""

footer = """$ns rtproto Static
$ns run\n"""

f = open(fn + '.ns', 'w')

f.write(header)
for i in range(n):
    f.write(set_node % (i, i, os, i, c_hw))
f.write('\n')

for j in range(m):
    f.write(set_server % (j, j, os, j, s_hw))
f.write('\n')

ctr = 0
for j1 in range(m):
    for j2 in range(j1):
        if j1 == j2:
            continue
        f.write(link % (ctr, j1, j2))
        ctr += 1
f.write('\n')

ctr = 0
for j in range(m):
    l = [('$node%d'%i) for i in range(n) if (i % m) == j]
    f.write(lan % (ctr, ' '.join(l), j, j, ctr))
    ctr += 1
f.write('\n')

f.write(footer)
