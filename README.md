# Logstash security plugins 

*These plugins help you in your security log analysis (close of SIEM but without post correlate, just real time) and make score for create alert.*

- logstash-filter-sig (filter plugin): analysis and detect security threat for make alert
- logstash-filter-ensig (filter plugin): enrich informations in event by different way (local databases, dynamic request, ...)
- logstash-output-fir (output plugin): push alert on FIR platform (CERT SG)

## logstash-filter-sig

*Logstash plugin Filter "Sig" can help you to detect security threat in log by differents ways.*

### Features

* Drop first time False positive and noise events
* Enrichissement event with database or/and send event to plugin enrsig for enrich event by active method (whois, ssl_check, nmap, ...)
* Drop second time False positive and noise events (based on enrichissement informations)
* Check new value in field
* Check blacklist reputation
* Check IOC in event (extracted on MISP)
* Check signatures with some fonctionnality:
  * Rule compisition:
    * Name: name of rule for report
    * ID: id use for correlate and change score
    * Score (note): give score if matched (use score for triggered alert)
    * Type: 2 types possibility, first is 'primary signature' and second is 'second signature'. Second signature match only if a primary signature matched before. 
    * ModeFP: it's boolean variable for indicate if rule match 'false positive'
    * extract (optional): use for extract data informations if you are sure that threat, and put in IOC local database for detect in all next events.
    * Use multi-search techniques (you can use one or more techniques in one rule) by event on field and value:
      * Check if field is present or field is not present
      * Check Regexp if present or not present
      * Check motif (Array or String)
      * Compare value field against another value field (string or numeric -- operator: ==, <, >, !=)
      * Check size (length) of string in field with operator: ==, <, >, !=
      * Check ipaddr (ex: 192.168.0.0/24) in field with operator: ==, !=
      * Check numeric value in field with operator: ==, !=, <, >
      * Check date value in relationship with time now + X, with operator: ==, <, >, !=
      * Check date value if in hour, use operator: ==, <, >, !=
      * Check date value if in day (number day, ex: 0==sunday,1==monday), use operator: ==, <, >, !=
      * Check frequence on multi event
        * Can be used for brute force (ex: if 3 times auth error in 60 secondes,then don't research before 3600 secondes)
        * Correlate multi-sources with same field value (ex: ip) on different events (ex: squid event IP DST == sysmon event IP DST) 
      * Check frequence on event
* Check event by compare with reference data (require to make reference database with ES when contains clean data) (it's new version of my project AEE [https://github.com/lprat/AEE])
  * Check size, check regexp form value, check if unique or determined list value (ex: don't be @timestamp because change everytime)    
  * Check link/relationship between not signle/determined list value of fields (idea inspired by tool PicViz [http://picviz.com/]). Exemple on apache log page test.php return always 200 in all logs. The link/relationship value/field is "uri_page(test.php)<->return_code(200)"
* Analys matched rules for adapt score of alert
* Fingerprint event according by rule for identify unique event & Drop fingerprint (false positive usage)
* Check frequence on specifique event by filters. Alert not created on a specifique event, but it create new event.

### Install by Docker

* You can use docker cloud: docker pull lprat/logstash-plugins:latest
*DockerFile create contener with last logstash and install plugin: sig, enrsig and fir. If you add others plugins, please edit Dockerfile before run docker composer*

Enter in directory "docker" and edit file "docker-compose.yml" :
* volumes: change volume source (on host) with your logstash path configuration

Before run docker composer, verify configuration logstash is valid. Verify configuration plugin logstash is valid too (use sample configuration in plugins directory for help you).

## logstash-filter-ensig

*Logstash plugin Filter "EnrSig" can help you to enrich event with different sources informations (database, system command, external request, ...).*
Normaly, enrsig is called by plugin "sig" (in begin check) according by the rules, it send event to logstash enrsig and it wait to reveive result on another input. When receive result, the enriched event goes back in sig filter.

### Features

* Check if enrichissement ask exist in the configuration (WHOIS, SSL_CHECK, NBTSCAN, NMAP, ...)
  * If exist, check if target field value exist and if format is valid (regexp)
    * Check if result exist already for value then pass to other ask, or if the end then send result
      * If data not exist then execute commande syntaxe with value(s) and parse result according by template, and pass to next ask or send result

### Install by Docker

*DockerFile create contener with last logstash and install plugin: sig, enrsig and fir. If you add others plugins, please edit Dockerfile before run docker composer*

Enter in directory "docker" and edit file "docker-compose.yml" :
* volumes: change volume source (on host) with your logstash path configuration

Before run docker composer, verify configuration logstash is valid. Verify configuration plugin logstash is valid too (use sample configuration in plugins directory for help you).

## logstash-output-fir

*Logstash plugin Output for send alert (created by filter sig) in FIR (Cert SG - https://github.com/certsocietegenerale/FIR)*

### Features

 * Create rule for send alert to FIR
 * Create or use default template to custom sent alert to FIR.
 * use fingerprint(sig plugin) for create one thread by IP SRC/MAC ADR in FIR for all alert

### Install by Docker

*Docker in cloud: lprat/logstash-plugins:latest
*DockerFile create contener with last logstash and install plugin: sig, enrsig and fir. If you add others plugins, please edit Dockerfile before run docker composer*

Enter in directory "docker" and edit file "docker-compose.yml" :
* volumes: change volume source (on host) with your logstash path configuration

Before run docker composer, verify configuration logstash is valid. Verify configuration plugin logstash is valid too (use sample configuration in plugins directory for help you).

* Lumberjack certificat
~~~
reference: https://github.com/logstash-plugins/logstash-output-lumberjack/issues/11
#Generate a CA, Key + Signed Cert
/opt/elasticsearch-6.4.2/bin/elasticsearch-certutil cert --pem
unzip certificate-bundle.zip

# Convert the key to PKCS8
openSSL pkcs8 -in ./instance/instance.key -topk8 -nocrypt -out ./instance/instance.pk8

###################################################################
#Upstream Logstash Server

# This input could be anything...
input {
  stdin {}
  }
}

# Send the output to a downstream server
output {
   lumberjack {
      codec => json
      hosts => [ "127.0.0.1" ]
      port => 5044
      ssl_certificate => "/Users/Downloads/lumberjack/certs/ca.crt"
   }
}

###################################################################
#Downstream Logstash Server
#
#  Using the BEATS input to receive data from the upsteam Logstash server
#  which is using the lumberjack output.
#
input {
  beats {
    id => "mylumberjack"
    codec => json
    port => 5044
    ssl_certificate => "/Users/Downloads/lumberjack/certs/instance.crt"
    ssl_key => "/Users/Downloads/lumberjack/certs/instance.pk8"
    ssl => true
  }

}

output {
   stdout { codec => rubydebug }
}
~~~

## Architecture sample (FR version)
![alt text](https://github.com/lprat/logstash-plugins/raw/master/sample-architecture/Architecture-sample.png "Architecture sample")
![alt text](https://github.com/lprat/logstash-plugins/raw/master/sample-architecture/Diagramme-archi.png "Diagramme architecture sample")

## Contact

@ lionel.prat9 (at) gmail.com Ou cronos56 (at) yahoo.com

