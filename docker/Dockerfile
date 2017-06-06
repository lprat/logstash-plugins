#Docker logstash with plugin output FIR && filter sig + enrsig
# Pull base image.
FROM logstash
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

#install simhash
RUN curl -sSL https://get.rvm.io | bash && /usr/local/rvm/bin/rvm install 1.9.3-dev
ADD mkmf.rb.patch /tmp/mkmf.rb.patch
RUN cd / && patch -Np1 /usr/share/logstash/vendor/jruby/lib/ruby/shared/mkmf.rb < /tmp/mkmf.rb.patch && rm /tmp/mkmf.rb.patch
#bug with install simhash direct, try to install activesupport version 5.x which require ruby 2.x
RUN env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem install activesupport -v '4.1.16'
RUN env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem install simhash -v '0.2.5'

#install plugins
RUN logstash-plugin install logstash-output-fir
RUN logstash-plugin install logstash-filter-sig
RUN logstash-plugin install logstash-filter-enrsig

#install others plugins
RUN logstash-plugin install logstash-output-lumberjack

#install extra for enrsig by example
#RUN apt-get update && apt-get install -y --no-install-recommends nbtscan python-whois && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["-e", ""]
