#!/bin/sh

install -m 755 ./localforwarding /sbin/localforwarding
install -m 644 ./localforwarding.yaml /etc/localforwarding.yaml
install -m 644 ./localforwarding.service /lib/systemd/system/localforwarding.service
