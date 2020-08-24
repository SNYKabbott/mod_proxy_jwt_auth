#!/bin/bash
# Build the RPMs and run the tests against them
# NOTE: This does not clean up Docker images
# WARNING: Must be run from the repo dir

set -x

RPMDIR="$(pwd)/RPMS"
if [ ! -d $RPMDIR ]; then
    mkdir $RPMDIR || exit 1
fi

export DOCKER_COMPOSE="docker-compose -f docker-compose.test.yml -p build${RANDOM}${RANDOM}${RANDOM}"

image_name=mod_proxy_jwt_auth:rpmbuild
if [ ! -z "$DEV_EAST_REPO" ]; then
    cache_image_name=${DEV_EAST_REPO}:mod_proxy_jwt_auth-cache
    docker_args=-t $cache_image_name
fi
container_name="mod_proxy_jwt_auth-${RANDOM}${RANDOM}"

[ ! -z "$DEV_EAST_REPO" ] && docker pull $cache_image_name || true
DOCKER_BUILDKIT=1 docker build --build-arg BUILDKIT_INLINE_CACHE=1 -f Dockerfile.rpmbuild -t $image_name $docker_args .
[ ! -z "$DEV_EAST_REPO" ] && docker push $cache_image_name || true
docker run --name $container_name $image_name
docker cp $container_name:/RPMS/. $RPMDIR
docker rm $container_name

$DOCKER_COMPOSE down -fsv
$DOCKER_COMPOSE build || exit 1
$DOCKER_COMPOSE run test_suite bundle exec rspec -fd
rv=$?
[ $rv ] || $DOCKER_COMPOSE logs
# Always run the down & rm steps to clean up
$DOCKER_COMPOSE down
$DOCKER_COMPOSE rm -fv
exit $rv
