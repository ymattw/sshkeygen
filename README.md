# sshkeygen

Generate ED25519 SSH key pairs that have public key containing a desired suffix.

## Usage

```
% make
% ./sshkeygen [-i] [-n numCores] <suffix>...
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

On a decent VPS with two workers, it can search ~72K key pairs per second:

- Searching a 3-letter suffix such as `/me` only takes a few seconds.
- Searching a 4-letter suffix such as `/git` takes a few minutes.
- Longer suffix might take a from a few hours up to a whole night.

As a real example, with two workers, it took me about only 1 hour to find this
cool key pair ([public key](https://github.com/ymattw.keys)):

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILSA8ZP10IhOrHcUSO35tlZvX4WIcqggt5nvKAA/Matt
```
