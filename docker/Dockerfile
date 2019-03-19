#Docker logstash with plugin output FIR && filter sig + enrsig
# Pull base image.
FROM docker.elastic.co/logstash/logstash:6.6.2
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

#install simhash
USER root
RUN yum update -y && yum groupinstall -y 'Development Tools'
USER logstash
RUN env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/2.3.0 /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem install activesupport -v '4.1.16'
RUN env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/2.3.0 /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem install simhash -v '0.2.5'

#install plugins
RUN logstash-plugin install logstash-output-fir
RUN logstash-plugin install logstash-filter-sig
RUN logstash-plugin install logstash-filter-enrsig

#install others plugins
RUN logstash-plugin install logstash-output-lumberjack

#install extra for enrsig by example
#RUN apt-get update && apt-get install -y --no-install-recommends nbtscan python-whois && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["-e", ""]
