#!/bin/bash
# Build the RPMs and run the tests against them
# NOTE: This does not clean up Docker images
# WARNING: Must be run from the repo dir

docker build --build-arg USER_UID=$(id -u) --build-arg USER_UID=$(id -g) -f Dockerfile.rpmbuild -t mod_proxy_jwt_auth:rpmbuild . || exit 1
docker run --rm -v $(pwd)/RPMS:/RPMS mod_proxy_jwt_auth:rpmbuild || exit 1

docker-compose -f docker-compose.test.yml build || exit 1
docker-compose -f docker-compose.test.yml run test_suite bundle exec rspec -fd
rv=$?
# Always run the down & rm steps to clean up
docker-compose -f docker-compose.test.yml down
docker-compose -f docker-compose.test.yml rm -fv
exit $rv
