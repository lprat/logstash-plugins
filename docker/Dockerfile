#Docker logstash with plugin output FIR && filter sig + enrsig
# Pull base image.
FROM logstash
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

#install simhash
RUN curl -sSL https://get.rvm.io | bash && /usr/local/rvm/bin/rvm install 1.9.3-dev
RUN sed '45 i ' /usr/share/logstash/vendor/jruby/lib/ruby/shared/mkmf.rb
ADD mkmf.rb.patch /tmp/mkmf.rb.patch
RUN cd / && patch -Np1 < /tmp/mkmf.rb.patch && rm /tmp/mkmf.rb.patch
RUN env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem install simhash -v '0.2.5'
#install plugin
RUN logstash-plugin install logstash-output-fir
RUN logstash-plugin install logstash-filter-sig
RUN logstash-plugin install logstash-output-enrsig

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["-e", ""]
