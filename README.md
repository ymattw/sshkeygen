# sshkeygen

Generate ED25519 SSH key pairs that have public key containing a desired suffix.

Example usage:

```
make

# Take multiple suffixes
./sshkeygen /matt /Matt

# Take multiple suffixes, and ignore case when comparing the suffix
./sshkeygen -i /matt ymattw

```

It took about a few hours to find a key pair with the public key matching
a 5-letter suffix on a MacBook M1 Pro with a single process.

Check out my cool public [key](https://github.com/ymattw.keys):

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILSA8ZP10IhOrHcUSO35tlZvX4WIcqggt5nvKAA/Matt
```
