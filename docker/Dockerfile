#Docker logstash with plugin output FIR && filter sig + enrsig
# Pull base image.
FROM logstash
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

#install simhash

RUN logstash-plugin install logstash-output-fir
RUN logstash-plugin install logstash-filter-sig
RUN logstash-plugin install logstash-output-enrsig

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["-e", ""]
