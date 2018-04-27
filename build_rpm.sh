#!/bin/bash
# Test: Run the test suite
# NOTE: This does not clean up Docker images
# WARNING: Must be run from the repo dir

set -eo pipefail

docker build --build-arg USER_UID=$(id -u) --build-arg USER_UID=$(id -g) -f Dockerfile.rpmbuild -t mod_request_env_jwt:rpmbuild .
docker run --rm -v $(pwd)/RPMS:/RPMS mod_request_env_jwt:rpmbuild
