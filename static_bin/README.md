# Binary files needed by the scionlab project

- `scion-pki` From scionproto, used to create TRCs.


## How-to build the binaries

### scion-pki

Use our fork of the scion project. Build scion normally, and copy the `scion-pki` binary to this directory in the scionlab project.


```
git clone -b scionlab_nextversion git@github.com:netsec-ethz/scion
cd scion
```

Now, if you want to use the regular `bazel` build (recommended):

```
./scion.sh bazelremote
make
```

Or just build with the go compiler:
```
go build -o ./bin/scion-pki ./go/scion-pki/
```

Finally, copy the binary located in `bin/scion-pki`.
