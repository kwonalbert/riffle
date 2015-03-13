import sys
import os
import hashlib

num_clients = int(sys.argv[1])
num_chunks = int(sys.argv[2])
block_size = eval(sys.argv[3])
dst_dir = sys.argv[4]

print 'block size: %d' % block_size

file_name = "file%d"

for i in range(num_clients):
    f = open("%s/%s" % (dst_dir, (file_name % i)), 'w')
    t = open("%s/%s" % (dst_dir, (file_name % i) + '.torrent'), 'w')
    for j in range(num_chunks):
        r = os.urandom(block_size)
        h = hashlib.sha224(bytearray(r)).digest()
        f.write(r)
        t.write(h)

