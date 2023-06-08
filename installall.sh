#!/bin/sh

install ./localforwarding /sbin/localforwarding
install ./localforwarding.yaml /etc/localforwarding.yaml
install ./localforwarding.service /lib/systemd/system/localforwarding.service
