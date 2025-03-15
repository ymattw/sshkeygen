# sshkeygen

Brute-force searching ED25519 SSH key pairs that have public key containing
desired suffixes.

## Usage

```
% make

% read -s PASSPHRASE; export PASSPHRASE
(enter a passphrase to protect the private key, optional)

% ./sshkeygen [-i] [-n numWorkers] <suffix>...
```

Options:

- `-i`: Ignore case when comparing the suffix
- `-n numWorkers`: Number of workers to utilize (default 1)

## Example usage

```
# Take multiple suffixes, fully utilize 2 cores, you will see 200% CPU usage
./sshkeygen -n 2 /matt /Matt

# Fully utilize all cores, ignore case when comparing the suffixes
./sshkeygen -n $(nproc) -i /matt ymattw
```

To stop the program, press `Ctrl+C`.

### Performance

On an Apple M1 Pro machine, running with 4 workers can search ~207K key pairs
per second.

On a decent VPS with 4 vCore 8G memory, running with 2 workers can search ~90K
key pairs per second.

So depending on your hardware -

- Searching a 3-letter suffix such as `/me` only takes a few seconds.
- Searching a 4-letter suffix such as `/git` takes a few minutes.
- Longer suffix might take a from a few hours up to a whole night.

As a real example, with 4 workers on Appe M1 Pro, it took me about only 1 hour
to find this cool key pair ([public key](https://github.com/ymattw.keys)).
