#!/bin/sh
#contact: lionel.prat9@gmail.com
#require: mkdir /opt/logstash-extra/ && cd /opt/logstash-extra/ && git clone https://github.com/CIRCL/PyMISP
rm -f /tmp/misp.json
python ./PyMISP/examples/last.py -l 90d -o /tmp/misp.json
python ./misp2json4ioc.py /tmp/misp.json /etc/logstash/db/ioc.json /etc/logstash/db/list_field_ioc ./blacklist.json
rm -f /tmp/misp.json
chown -R logstash.logstash /etc/logstash/db
