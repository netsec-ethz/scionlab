# Binary files needed by the scionlab project

- `scion-pki` from netsec-ethz/scion, used to create TRCs.

  This binary is directly contained in the scionlab repository. 
  This allows us to simply guarantee that we use the same dependency version
  during development, e.g. for running tests, and in the production deployment,
  without relying on external services. 
  The alternative of e.g. installing from our debian packages would introduce
  tricky constraints to the release sequence -- the coordinator would require
  updated packages to function, but at the same time the coordinator should be
  available to serve updated configuration at the time the packages are
  released.


## How to update

Requires docker.

1. Modify the `scion_commit` hash in the Dockerfile & update the date of the
   commit in the comment.
2. Run `build.sh`; this will build `scion-pki` (using `go build`) in a docker
   container and copy the resulting binary to this directory.
3. Commit the modified `Dockerfile` and `scion-pki`
