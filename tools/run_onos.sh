source ~/.bash_profile &&
cd $ONOS_ROOT &&
export ONOS_APPS=$ONOS_APPS,fwd &&
env &&
bazel run onos-local --jobs=10 --action_env=HTTP_PROXY=$http_proxy -- clean debug