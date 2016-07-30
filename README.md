# Riffle

This is a research prototype of
[Riffle](https://people.csail.mit.edu/devadas/pubs/riffle.pdf), an
anonymous communication system presented at
[PETS2016](https://www.petsymposium.org/). This models the performance
of the system and carries out the core parts of the protocol, but not
necessarily in a secure way. In other words, this prototype implements
most of what's described in the paper, but does NOT make any
guarantees about security. It is almost certainly full of security
bugs. Please do not adapt this code to use for real anonymous
communication.

## Requirements

Requires Go 1.5 or later for building the code, and the
scripts are written for python2 (not 3).

It uses the [DeDis Crypto library](https://github.com/dedis/crypto)
as well as [SecretBox](http://golang.org/x/crypto/nacl/secretbox) of
NaCl and [sha3](http://golang.org/x/crypto/sha3).

## Components

* server: the mixing servers in the network (assumed to be handful many)

* client: the clients who either send or receive messages

## Building Riffle

Build the two by running

  $ go install ./client ./server

## Running tests

Clients can run in two modes: file sharing and microblogging.

### File sharing

For file sharing, we assume each client has a file and they download a
file. This prototype assumes the "optimal" case, in that in each
round, there is a 1 to 1 mapping between files and clients.  In a real
implementation where this is not the case, there are a few solutions,
the easiest being having the client request the file again if the file
(block) is not available at the end of the round (but these solutions
have not been implemented in this mode). In each round, a chunk of
file is uploaded.

To run this, you need to first generate the files. To do so, run

  $ python2 ./scripts/gen_file.py <num_clients> <num_blocks> <block_size> <dst_dir>

* num_clients: number of clients in the system, and thus number of
 files to generate

* num_blocks: number of blocks (chunks) in a file, and thus number of
 rounds

* block_size: size of each block. This needs to be the same as the
 block size in params.go in lib.

* dst_dir: destination folder for all the files. You will want to just
 create a folder (e.g., called files).


### Microblogging

For microblogging, each client submits a small message, and the result
is broadcast to everyone. Currently, it just sends random messages.

### Running a local test
You can run a local test, where each server runs on a port on
localhost, by running

  $ python2 ./scripts/test_local.py <num_servers> <num_clients> <mode> <file_dir>

* num_servers: number of servers in the test

* num_clients: number of clients

* mode: 'm' for microblogging test, and 'f' for file sharing test

* file_dir: where the files are, if running file sharing test. Should
 be the same as <dst_dir> for gen_file script.


### Running remote test

Coming soon. A modified version of the local test script can do this
easily.
