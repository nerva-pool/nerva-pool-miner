# NERVA POOL MINER

## Compiling from source

```
git clone --recursive https://github.com/nerva-pool/nerva-pool-miner.git
cd nerva-pool-miner
./builder/dependencies
make release
```

[Building the NERVA CLI tools](https://bitbucket.org/snippets/nerva-project/kejLB4/building-the-nerva-cli-tools): To build and run the CLI tools

[NERVA CLI: Getting Started](https://bitbucket.org/snippets/nerva-project/KeLrBy/nerva-cli-getting-started): To get the basics on how to create a wallet and mine NERVA, along with some useful information on common commands

## Example

Just replace *&lt;address&gt;* with your Nerva address.

```
nervad --start-mining <address> --mining-threads 4
```

Once NERVA is synced, you should see some messages along the lines of:

```
2020-04-20 10:32:22.676 I Pool mining to nerva.pooled.work:4444
2020-04-20 10:32:22.677 I Mining has started with 4 threads, good luck!
2020-04-20 10:32:22.884 I New Job: height: 1035621 target: 18446742802399232
2020-04-20 10:32:24.990 I Found share at height: 1035621 nonce:516700416 pow: <2805db85e36713bc8b6c6bc3db10aacb19ff5c0b630c6c6527589a88b8e02900> di: 11787557215557671 target: 18446742802399232
```

## FAQ

### Why

Because the NERVA PoW is not pool resistant.

### Why do I need to sync the blockchain?

The NERVA PoW requires the block data.

### So then this is not a 'real' pool miner, it's still decentralized, right?

The block data is decentralized, but not the concentration of hashing power. The pool delegates the work, so it is indeed pool mining.
It's of course possible to create a mining pool that pushes the block headers to the miners without them participating in the p2p network, or worse to create a miner that only leeches off the network. Ultimately, what good is block distribution if the pool controls the chain?

## License

See [LICENSE](LICENSE).

## Where to get help

Discord is the preferred method of communication for NERVA

[Discord](https://discord.gg/jsdbEns)


