# Logstash Plugin

Logstash plugin Filter "Sig" can help you to detect security threat in log by differents techniques:
* Drop False positive and noise
* IOC extracted of MISP by exemple
* Find new value in field
* SIG with some fonctionnality search
  * Each rule have:
    * a name: name of rule for report
    * a id: id use for correlation and change note
    * a score (note): give score to signature, use for trigger alert or no
    * a type: two type, one (1) is primary signature and two (2) is second signature. Second signature match only if a primary signature has before matched.
    * ModeFP: true if false positive signature
    * extract (optionnal): use for extract data information which you are sure that threat, and put in IOC local database for detect in all next events.
  * Each rule can to do multi search technique by event on field and value:
    * Field present and Field not present
    * Regexp
    * Regexp not present
    * motif: motif must Array type and contains all possibility match
    * Compare value field with another value field (string or numeric -- operator: ==, <, >, !=)
    * Check size of string (length) operator: ==, <, >, !=
    * Check ipaddr (ex: 192.168.0.0/24) with operator: ==, !=
    * Check numeric value with operator: ==, !=, <, >
    * Check date value in relationship with time now + X, use operator: ==, <, >, !=
    * Check date value if in hour, use operator: ==, <, >, !=
    * Check date value if in day (number day, ex: 0==sunday,1==monday), use operator: ==, <, >, !=
    * Check frequence on multi event
      * use for brute force (ex: sig type 3times error auth in 60secondes, if detected not research before 3600 secondes)
      * use for correlation multi source with field value common (ex: ip) on events but different event type (squid and antivirus) (ex: sig type one error/detect on each type)
    * Check frequence on event second possibility use for correlation
* By databases of reference (before make with ES data contains clean logs -- script include) (new version of my project AEE [https://github.com/lprat/AEE])
  * Check size, check regexp data, uniq value (ex: uniq value can be @timestamp because change everytime)
  * Check link/relationship between not uniq (value) fields (idea inspired by tool PicViz). Exemple on apache log page test.php return always 200 in all logs. The link/relationship val$
* Note/Score functionnality for change score (up or down) of alert with correlation IOC/multi SIG/REF match
* By frequence but create alert not defined reason, just know log loading up and not normaly. You can select frequence on specifique event by filters

This plugin use simhash for find around result and futur possibility check and correlation.

**!!!! You must install simhash under logstash, follow instruction:** 

1. curl -sSL https://get.rvm.io | bash && /usr/local/rvm/bin/rvm install 1.9.3-dev
2. IN vendor/jruby/lib/ruby/shared/mkmf.rb add line (45):
  * RbConfig::MAKEFILE_CONFIG["CPPFLAGS"] += ' -I/usr/local/rvm/rubies/ruby-1.9.3-p551-dev/include/ruby-1.9.1/x86_64-linux/'
  * RbConfig::MAKEFILE_CONFIG['includedir'] = "/usr/local/rvm/rubies/ruby-1.9.3-p551-dev/include/ruby-1.9.1/"
3. env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/bundle/jruby/1.9/bin/bundle install
4. env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem build logstash-filter-sig.gemspec
5. /usr/share/logstash/bin/logstash-plugin install logstash-filter-sig-3.0.0.gem 

** You welcome to contribute (report bug, new functionality, ...)! **

** Possibility you meet bug, I recently ported on logstash 5.x !! ** 

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Contact
Lionel PRAT lionel.prat9 (at) gmail.com or cronos56 (at) yahoo.com

## Let's start with docker
Dockerfile
```
FROM logstash
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

RUN apt-get update && apt-get install -y vim nano
RUN mkdir -p /opt/logstash-plugins/ && mkdir /etc/logstash/db
ADD logstash-filter-sig /opt/logstash-plugins/
RUN cp /opt/logstash-plugins/logstash-filter-sig/conf-samples/* /etc/logstash/db/ && chown logstash.logstash -R /etc/logstash/db/
RUN cp /opt/logstash-plugins/logstash-filter-sig/need/mkmf.rb /usr/share/logstash/vendor/jruby/lib/ruby/shared/mkmf.rb 
RUN cd /opt/logstash-plugins/logstash-filter-sig && curl -sSL https://get.rvm.io | bash && /usr/local/rvm/bin/rvm install 1.9.3-dev && env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/bundle/jruby/1.9/bin/bundle install && env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem build logstash-filter-sig.gemspec
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-sig-3.0.0.gem
```

## Main Configuration (logstash-filter.conf)
** Refresh DB : The plugin use some files configurations, you can change it during run. The plugin get change and apply all refresh time. You can use config/db file with git system... ** 
** Functions are in order to works/process **
* Disable check techniques : use for disable function check
  * no_check => "sig_no_apply_all" : add in event a field name "sig_no_apply_all" for no use all check on it
  * disable_drop => false :  if turn to true, function "drop" will disable
  * disable_fp => false :  if turn to true, function "fingerprint & drop fingerprint" will disable
  * disable_nv => false :  if turn to true, function "new value" will disable
  * disable_ioc => false :  if turn to true, function "ioc" will disable
  * disable_sig => false :  if turn to true, function "signature" will disable
  * disable_ref => false :  if turn to true, function "reference" will disable
  * disable_freq => false :  if turn to true, function "frequence" will disable
  * disable_note => false :  if turn to true, function "note/score" will disable

* Drop function : use drop function to drop noise and event you don't want analysis
  * noapply_sig_dropdb => "sig_no_apply_dropdb" : add in event a field name "sig_no_apply_dropdb" for no use this check on it
  * db_drop => "/etc/logstash/db/drop-db.json" : path of file drop-db.json (see below for more information)
  * refresh_interval_dropdb => 3600 : delay interval (in second) to refresh db_drop

* New value : use for check new value on event specified field
  * conf_nv => "/etc/logstash/db/new.json" : path of file new.json (see below for more information)
  * db_nv => "/etc/logstash/db/new-save.json" : path of file new-save.json (see below for more information)
  * noapply_sig_nv => "sig_no_apply_nv" : add in event a field name "sig_no_apply_nv" for no use this check on it
  * refresh_interval_confnv => 3600 : delay interval (in second) to refresh conf_nv
  * save_interval_dbnv => 3600 : delay interval (in second) to save db_nv 
  * target_nv => "new_value_" : prefix value if new value detected, create field with name "new_value_FIELDX" contains "new value" value

* IOC : use for check IOC in event
  * db_ioc => ["/etc/logstash/db/ioc.json", "/etc/logstash/db/ioc_local.json"] : Array contains path of files db (ioc_local.json => created by signature function [file_save_localioc], ioc.json) (see below for more information)
  * conf_ioc => "/etc/logstash/db/ioc_conf.json" : path of file ioc_conf.json (see below for more information)
  * target_ioc => "ioc_detected" : name of field where you save IOC detected
  * targetnum_ioc => "ioc_detected_count" : name of field where you save count of IOC detected
  * targetname_ioc => "ioc_detected_name" : name of field where you save IOC name detected
  * refresh_interval_dbioc => 3600 : delay interval (in second) to refresh conf_ioc & db_ioc
  * noapply_ioc => "sig_no_apply_ioc" : add in event a field name "sig_no_apply_ioc" for no use this check on it
  
* Signature : use for check complexe signature on event
  * conf_rules_sig => "/etc/logstash/db/sig.json" : path of file sig.json (see below for more information)
  * file_save_localioc => "/etc/logstash/db/ioc_local.json" : path of file ioc_local.json (see below for more information)
  * target_sig => "sig_detected" : name of field where you save Rules detected
  * targetnum_sig => "sig_detected_count" : name of field where you save count of rules detected
  * targetname_sig => "sig_detected_name" : name of field where you save name of rules detected
  * refresh_interval_confrules => 3600 : delay interval (in second) to refresh file_save_localioc & conf_rules_sig
  * noapply_sig_rules => "sig_no_apply_rules" : add in event a field name "sig_no_apply_rules" for no use this check on it
  * check_stop => false : fix to true if you can stop check sig after one found
  
* REFERENCE (old ANOMALIE) : use for verify event is included in reference database
  * conf_ref => "/etc/logstash/db/conf_ref.json" : path of file conf_ref.json (see below for more information)
  * db_ref => "/etc/logstash/db/reference.json" : path of file reference.json (see below for more information)
  * db_pattern => "/etc/logstash/db/pattern.db" : path of file pattern.db (see below for more information)
  * refresh_interval_dbref => 3600 : delay interval (in second) to refresh db_ref & db_pattern & conf_ref
  * noapply_ref => "sig_no_apply_ref" : add in event a field name "sig_no_apply_ref" for no use this check on it
  * target_ref => "ref_detected" : name of field where you save detected differences between event and reference
  * targetnum_ref => "ref_detected_count" : name of field where you save count all detected differences between event and reference
  * targetname_ref => "ref_detected_name" : name of field where you save detected name of difference between event and reference
  * ref_aroundfloat => 0.5 : around score if not integer (float result)
  * ref_stop_after_firstffind => true : fix to false if you can continue to check reference after one rule found
  
* SIG & IOC & REF configuration common (SCORE/NOTE function) : use score function for change value of score if you match multi rule (IOC/REF/SIG ==> correlation between matched) 
  * targetnote => "sig_detected_note" : name of field where you save score issued of IOC/SIG/REF/SCORE function
  * targetid => "sig_detected_id" : name of field where you save ID rule issued of IOC/SIG/REF function
  * conf_rules_note => "/etc/logstash/db/note.json" : path of file note.json (see below for more information)
  
* Fingerprint function: use for limit information on alert, first detect add fingerprint value and 'first' tag, after all others add tag 'info' (information complementary). You can process for make alert with first (send to incident platform) and put all 'info' in ES for read for more context information.
  * noapply_sig_dropfp => "sig_no_apply_dropfp" : add in event a field name "sig_no_apply_dropfp" for no use this check on it
  * conf_fp => "/etc/logstash/db/fingerprint_conf.json" : path of file fingerprint_conf.json (see below for more information)
  * db_dropfp => "/etc/logstash/db/drop-fp.json" : path of file drop-fp.json (see below for more information)
  * select_fp => "tags" : name field for select/filter type, relationship with fingerprint_conf.json. Exemple: event['tags']="squid" --> (fingerprint_conf.json->>) {"squid":{"fields":[....],...}}
  * target_fp => "fingerprint" : name field where you save fingerprint value
  * tag_name_first => "first_alert" : value name of tag for unique event alert when first time to lookup
  * tag_name_after => "info_comp" : value name of tag for unique event alert when not first time to lookup
  * target_tag_fp => "tags" : field name where you save the value tag (first or complementary)
  * refresh_interval_conffp => 3600 : delay interval (in second) to refresh db_dropfp and conf_fp

* FREQUENCE : use for detect anormaly frequence increase on event flux
  * conf_freq => "/etc/logstash/db/conf_freq.json" : path of file conf_freq.json (see below for more information)
  * refresh_interval_freqrules => 3600 : delay interval (in second) to refresh conf_freq
  * noapply_freq => "sig_no_apply_freq" : add in event a field name "sig_no_apply_freq" for no use this check on it
  
## Files Configuration
** Check in folder conf-samples and scripts-create-db **
### DROP FIRST
The file drop-db.json contains rule for drop event, that you don't want analysis or noise.
** This file is a Json format **
```
{"dst_domain": "^google.com$|^mydomain.ext$", "dst_ip": "10.0.0.\\d+"}
```
The json key is field name to check in event (event['field'], and value must regexp to check on it. If regexp match then event is dropped.

### New Value
#### new-save.json
The file is auto generated by plugins, but you must created for first time with contains '{}' (Json empty). In time, contains all informations of field selected.
You can restart to 0 by recreate file.
** This file is a Json format **
#### new.json
The file contains rules which indicates what field selected for check new value.
** This file is a Json format **
```
{"rules": ["dst_host","user_agent"]}
```
Above, the rules selectes field with name "dst_host" for create verification on it, and another verification on field "user_agent".

### IOC
#### ioc_conf.json
This file contains rules which explain on which field use each IOC. 
A rule is hash composed of 4 elements:
* First key: IOC name in DB with value include in event key (ex: "ioc_hostname":["_host"] want to do => check IOC hostname on event with field name *_host* as event['dst_hostname'] ... )
* Second Key Name repeat First key name with add +'_downcase', it's value can be true or false. True verify IOC without case (AbC == abc) and False opposite (AbC != abc)
* Third key name repeat again and add +'iocnote', it's value is score if IOC detected
* Fourth key name repeat again! and add +'iocid', it's value is ID of rule for use after in NOTE function by example.
** This file is a Json format **
```
{
"ioc_hostname":["_host"], "ioc_hostname_downcase":true, "ioc_hostname_iocnote":2, "ioc_hostname_iocid":1001,
"ioc_domain":["_domain"], "ioc_domain_downcase":true, "ioc_domain_iocnote":2, "ioc_domain_iocid":1002,
"ioc_ip":["_ip"], "ioc_ip_downcase":false, "ioc_ip_iocnote":1, "ioc_ip_iocid":1003,
"ioc_emailaddr":["_emailaddr"], "ioc_emailaddr_downcase":true, "ioc_emailaddr_iocnote":3, "ioc_emailaddr_iocid":1004,
"ioc_user-agent":["user_agent"], "ioc_user-agent_downcase":false, "ioc_user-agent_iocnote":2, "ioc_user-agent_iocid":1005,
"ioc_uri":["_url","_request","_uripath_global"], "ioc_uri_downcase":false, "ioc_uri_iocnote":2, "ioc_uri_iocid":1006,
"ioc_attachment":["attachment","_uriparam","_uripage"], "ioc_attachment_downcase":false, "ioc_attachment_iocnote":1, "ioc_attachment_iocid":1007
}
```

#### ioc_local.json
This file is generated (JSON format) by plugin with use function signature and parameter 'extract'.
** For first time, you create file empty (echo '{}' > ioc_local.json) ** 

#### Script to generate ioc.json
Use script ioc_create.sh for create ioc.json file (in path: "/etc/logstash/db/") from MISP db.
** Require Pymisp (https://github.com/MISP/PyMISP), wget (for download alexa db), misp2json4ioc.py (include in folder scripts), blacklist.json (include in conf-samples) **

##### blacklist.json
This file used for avoid to add IOC create more false positive.
** This file is a Json format **
```
{
"ioc_ip":["(127\\.[0-9]+\\.[0-9]+\\.[0-9]+|10\\.\\d+\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+|172\\.([1-2][0-9]|0|30|31)\\.\\d+\\.\\d+|255\\.255\\.255\\.\\d+)"], 
"email-attachment":[],
"ioc_attachment":["2"],
"ioc_emailaddr":[],
"ioc_uri":["\/"],
"ioc_domain":[],
"ioc_hostname":[],
"ioc_user-agent":[],
"ioc_email-subject":[],
"ioc_as":[]
}
```

### SIGNATURES
The sig.json file contains rules to check in event.
THe first key name is 'rules', the value is array contains all rules.
Each rule is Hash composed of multi element optionnal and mandatory:
* Level 1 : all first key in hash is name of Field {fieldX:{},fieldY:{},...} with techniques of search, for rule match, you must valid match on all technique in all field!
  * In one field (only) you must add information (in its hash): 
    * "id": X => X is value interger of key id, give unique id number which identify rule
    * "name": "String" => String is a value string which give name to rule
    * "type": value 1 or 2 => use 1 for search rule in event without another rule before find, and use 2 for search only if a rule is found before.
    * "note": 1 to X => use for give the score if rule match
    * "modeFP": true or false => use for drop event if rule match (false positive mode)
    * "extract": {"field": "ioc_x"} => ** it's optionnal add ** , use for extract value of field indicated in hash key and put in ioc database local in ioc_X selected in value of hash.
    * Technique frequence & correlation in different event:
       * "freq_field": [fieldx,fieldz,...] => the value is array contains name of field of event relationship between anoter event 
       * "freq_delay": x in second => it's time delay between first event and last event (if freq_count == 3 then first 1 and last 3)
       * "freq_count": y => the count of event you must see for match
       * "freq_resettime": z in second => the time to wait for reseach new frequence when you before detected
       * "correlate_change_fieldvalue": [] => indicated field name in array, the value of field must be different for each event match
  * Techniques of search
    * "motif": ["X","Z"] => use for search motif in field. Field must include one element in array. If field contains X then techniques match!
    * "false": {} => flase contais empty hash. use for indicate than field name not be present in event
    * "regexp": ["^\\d+$","..."] => value is array contains all regexp, for match technique each regexp must matched. 
    * "notregexp": [] => value is array contains all regexp, for match technique each regexp must ** not ** matched.
    * "date": {'egal'|'inf'|'sup'|'diff': x in second} => use for field contains date value, check if date is (time.now)-x  of value with operator (<,>,!=,==) 
    * "hour": {'egal'|'inf'|'sup'|'diff': 0 to 23} => use for field contains date value, check if hour is hour of value with operator (<,>,!=,==)
    * "day": {'egal'|'inf'|'sup'|'diff': 0 to 6} => use for field contains date value , check if day is day of value with operator (<,>,!=,==)
    * "ipaddr": {'egal'|'diff']: ipaddr or subnet} => use on field contains ip addr compare if value (by operator != or ==) to value of hash
    * "sizeope" : {['egal'|'inf'|'sup'|'diff']: x} => use on field contains string and compare size of string with hash operator for value hash.
    * "numop" : {['egal'|'inf'|'sup'|'diff']: x} => use on field contains interger and compare number with hash operator for value hash.
    * "compope": {"fieldz": {['egal'|'inf'|'sup'|'diff']: "string"/numeric}} => use for compare two field in same event with same value type
    * ** !! two another techniques present in information party above **

** This file is a Json format  -- example not use all possibility of sig **
```
{"rules":[
	{"type":{"motif":["squid"],"type":1,"note":1,"name":"Field User-AGENT not present","id":1},"user_agent":{"false":{}}},
        {"new_value_dst_host":{"sizeope":{"sup":1},"type":1,"note":1,"name":"New value dst_host","id":2},"type":{"motif":["squid"]}},
	{"elapsed_time":{"numope":{"sup":900000},"type":1,"note":2,"name":"Connection time too long > 15minutes","id":3}},
	{"type":{"motif":["squid"],"type":2,"note":2,"name":"Referer FIELD not present","id":4},"uri_proto":{"notregexp":["tunnel"]},"referer_host":{"false":{}}}
]}
```
### REFERENCE (OLD ANOMALIE)
#### conf_ref.json
This file contains rules to check on event and also use for create databases reference (script).
The file json contains a key named 'rules' and this value is Array which contains all rules.
A rule is composed of multi elements:
* Key "pivot_field" : use for filter event by rule (select rule), value is hash with key is event field name, and value is Array which contains value which must present in event field.
* Key "list_sig" : value is Array contains name of field in event checked in reference databases. If field not present in some case, it's doesn't matter. 
* Key "relation_min" : value is integer, used in relationship between field on field not unique. This relationship create simhash, the reference databases contains count of simhash value seem in all event type. Exemple if simhash "1111111" count 9 time in all event then if you set 10 this parameter, the plugins match rule because relationship not exist for him/it.
* Key "simhash_size" : value is integer, use for create simhash size... If you use little value then you more chance you find value simhash with event near.
* Key "simhash_use_size" (Not works, i will work on!)
* Key "id" : use for identified rule matched and used in score/note function.

** This file is a Json format **
```
{"rules":[ 
  {"pivot_field":{"tags":["squid"]}, "list_sig": ["src_host","src_ip","dst_host","dst_ip","uri_proto","uri_global"], "relation_min": 10, "simhash_size": 32, "simhash_use_size": 32, "id": 2001}
]}
```
#### Create reference database (reference.json)
For create databases (reference.json file) use script include in scripts folder.
Run script with syntaxe: ./create.rb conf_ref.json pattern.db  https://user:secret@localhost:9200
For make good databases, use elasticsearch contains clean data log else you verify databases containt and change strange value.

##### note_ref_defaut.json
This file contains note/score by default for each check of reference verification matched.
The 'NOTE_UNIQ_REDUC' used for reduce score of matched on field check. By example if match LEN problem then if uniq field value, score is not 0.25 but 0.25-0.1 => 0.15.
** This file is a Json format **
```
{
	'NOTE_UNIQ_REDUC': 0.1, 
	'NOTE_DEFAULT': 2,
	'NOTE_LISTV': 0.25,
	'NOTE_ENCODING': 0.25,
	'NOTE_LEN': 0.25,
	'NOTE_LEN_AVG': 0.25,
	'NOTE_LEN_EVEN': 0.25,
	'NOTE_REGEXP': 0.25,
	'NOTE_REGEXP_MIN': 0.25
	}
```
##### pattern.db  
This file is used in check of regexp on field value.
This file is ** not ** a Json format.
```
ALPHA_MAJU=>>[A-Z]
ALPHA_MINU=>>[a-z]
NUM_1to9=>>[1-9]
NUM_0to9=>>[0-9]
ALPHA_MAJandMIN=>>[A-Za-z]
HEXA=>>(0x|x|\\x)[0-9A-Fa-f][0-9A-Fa-f]
CHAR_SPE_NUL=>>\x00
CHAR_SPE_SOH=>>\x01
CHAR_SPE_STX=>>\x02
CHAR_SPE_ETX=>>\x03
CHAR_SPE_EOT=>>\x04
CHAR_SPE_ENQ=>>\x05
CHAR_SPE_ACK=>>\x06
CHAR_SPE_BEL=>>\x07
CHAR_SPE_BS=>>\x08
CHAR_SPE_HT=>>\x09
CHAR_SPE_LF=>>\x0A
CHAR_SPE_VT=>>\x0B
CHAR_SPE_FF=>>\x0C
CHAR_SPE_CR=>>\x0D
CHAR_SPE_SO=>>\x0E
CHAR_SPE_SI=>>\x0F
CHAR_SPE_DLE=>>\x10
CHAR_SPE_DC1=>>\x11
CHAR_SPE_DC2=>>\x12
CHAR_SPE_DC3=>>\x13
CHAR_SPE_DC4=>>\x14
CHAR_SPE_NAK=>>\x15
CHAR_SPE_SYN=>>\x16
CHAR_SPE_ETB=>>\x17
CHAR_SPE_CAN=>>\x18
CHAR_SPE_EM=>>\x19
CHAR_SPE_SUB=>>\x1A
CHAR_SPE_ESC=>>\x1B
CHAR_SPE_FS=>>\x1C
CHAR_SPE_GS=>>\x1D
CHAR_SPE_RS=>>\x1E
CHAR_SPE_US=>>\x1F
CHAR_SPE_SP=>>\x20
CHAR_SPE_EXCL=>>\x21
CHAR_SPE_QUOTE=>>\x22
CHAR_SPE_DIEZ=>>\x23
CHAR_SPE_DOLLAR=>>\x24
CHAR_SPE_POURC=>>\x25
CHAR_SPE_AND=>>\x26
CHAR_SPE_QUOTE2=>>\x27
CHAR_SPE_DPARA=>>\x28
CHAR_SPE_FPARA=>>\x29
CHAR_SPE_ETOI=>>\x2A
CHAR_SPE_PLUS=>>\x2B
CHAR_SPE_VIRG=>>\x2C
CHAR_SPE_MOINS=>>\x2D
CHAR_SPE_POINT=>>\x2E
CHAR_SPE_SLASH=>>\x2F
CHAR_SPE_2POINT=>>\x3A
CHAR_SPE_POINTVIRG=>>\x3B
CHAR_SPE_DBALIZ=>>\x3C
CHAR_SPE_EGAL=>>\x3D
CHAR_SPE_FBALIZ=>>\x3E
CHAR_SPE_INTER=>>\x3F
CHAR_SPE_AROB=>>\x40
CHAR_SPE_DCROCH=>>\x5B
CHAR_SPE_ASLASH=>>\x5C
CHAR_SPE_DCROCH=>>\x5D
CHAR_SPE_CHAP=>>\x5E
CHAR_SPE_UNDERS=>>\x5F
CHAR_SPE_QUOTE3=>>\x60
CHAR_SPE_DACCOL=>>\x7B
CHAR_SPE_OR=>>\x7C
CHAR_SPE_FACCOL=>>\x7D
CHAR_SPE_TILD=>>\x7E
CHAR_SPE_DEL=>>\x7F
CHAR_ETEND_80=>>\x80
CHAR_ETEND_81=>>\x81
CHAR_ETEND_82=>>\x82
CHAR_ETEND_83=>>\x83
CHAR_ETEND_84=>>\x84
CHAR_ETEND_85=>>\x85
CHAR_ETEND_86=>>\x86
CHAR_ETEND_87=>>\x87
CHAR_ETEND_88=>>\x88
CHAR_ETEND_89=>>\x89
CHAR_ETEND_8A=>>\x8A
CHAR_ETEND_8B=>>\x8B
CHAR_ETEND_8C=>>\x8C
CHAR_ETEND_8D=>>\x8D
CHAR_ETEND_8E=>>\x8E
CHAR_ETEND_8F=>>\x8F
CHAR_ETEND_90=>>\x90
CHAR_ETEND_91=>>\x91
CHAR_ETEND_92=>>\x92
CHAR_ETEND_93=>>\x93
CHAR_ETEND_94=>>\x94
CHAR_ETEND_95=>>\x95
CHAR_ETEND_96=>>\x96
CHAR_ETEND_97=>>\x97
CHAR_ETEND_98=>>\x98
CHAR_ETEND_99=>>\x99
CHAR_ETEND_9A=>>\x9A
CHAR_ETEND_9B=>>\x9B
CHAR_ETEND_9C=>>\x9C
CHAR_ETEND_9D=>>\x9D
CHAR_ETEND_9E=>>\x9E
CHAR_ETEND_9F=>>\x9F
CHAR_ETEND_A0=>>\xA0
CHAR_ETEND_A1=>>\xA1
CHAR_ETEND_A2=>>\xA2
CHAR_ETEND_A3=>>\xA3
CHAR_ETEND_A4=>>\xA4
CHAR_ETEND_A5=>>\xA5
CHAR_ETEND_A6=>>\xA6
CHAR_ETEND_A7=>>\xA7
CHAR_ETEND_A8=>>\xA8
CHAR_ETEND_A9=>>\xA9
CHAR_ETEND_AA=>>\xAA
CHAR_ETEND_AB=>>\xAB
CHAR_ETEND_AC=>>\xAC
CHAR_ETEND_AD=>>\xAD
CHAR_ETEND_AE=>>\xAE
CHAR_ETEND_PD=>>\xAF
CHAR_ETEND_B0=>>\xB0
CHAR_ETEND_B1=>>\xB1
CHAR_ETEND_B2=>>\xB2
CHAR_ETEND_B3=>>\xB3
CHAR_ETEND_B4=>>\xB4
CHAR_ETEND_B5=>>\xB5
CHAR_ETEND_B6=>>\xB6
CHAR_ETEND_B7=>>\xB7
CHAR_ETEND_B8=>>\xB8
CHAR_ETEND_B9=>>\xB9
CHAR_ETEND_BA=>>\xBA
CHAR_ETEND_BB=>>\xBB
CHAR_ETEND_BC=>>\xBC
CHAR_ETEND_BD=>>\xBD
CHAR_ETEND_BE=>>\xBE
CHAR_ETEND_BF=>>\xBF
CHAR_ETEND_C0=>>\xC0
CHAR_ETEND_C1=>>\xC1
CHAR_ETEND_C2=>>\xC2
CHAR_ETEND_C3=>>\xC3
CHAR_ETEND_C4=>>\xC4
CHAR_ETEND_C5=>>\xC5
CHAR_ETEND_C6=>>\xC6
CHAR_ETEND_C7=>>\xC7
CHAR_ETEND_C8=>>\xC8
CHAR_ETEND_C9=>>\xC9
CHAR_ETEND_CA=>>\xCA
CHAR_ETEND_CB=>>\xCB
CHAR_ETEND_CC=>>\xCC
CHAR_ETEND_CD=>>\xCD
CHAR_ETEND_CE=>>\xCE
CHAR_ETEND_CF=>>\xCF
CHAR_ETEND_D0=>>\xD0
CHAR_ETEND_D1=>>\xD1
CHAR_ETEND_D2=>>\xD2
CHAR_ETEND_D3=>>\xD3
CHAR_ETEND_D4=>>\xD4
CHAR_ETEND_D5=>>\xD5
CHAR_ETEND_D6=>>\xD6
CHAR_ETEND_D7=>>\xD7
CHAR_ETEND_D8=>>\xD8
CHAR_ETEND_D9=>>\xD9
CHAR_ETEND_DA=>>\xDA
CHAR_ETEND_DB=>>\xDB
CHAR_ETEND_DC=>>\xDC
CHAR_ETEND_JJ=>>\xDD
CHAR_ETEND_DE=>>\xDE
CHAR_ETEND_D=>>\xDF
CHAR_ETEND_E0=>>\xE0
CHAR_ETEND_E1=>>\xE1
CHAR_ETEND_E2=>>\xE2
CHAR_ETEND_E3=>>\xE3
CHAR_ETEND_E4=>>\xE4
CHAR_ETEND_E5=>>\xE5
CHAR_ETEND_E6=>>\xE6
CHAR_ETEND_E=>>\xE7
CHAR_ETEND_E8=>>\xE8
CHAR_ETEND_E9=>>\xE9
CHAR_ETEND_EA=>>\xEA
CHAR_ETEND_EB=>>\xEB
CHAR_ETEND_EC=>>\xEC
CHAR_ETEND_ED=>>\xED
CHAR_ETEND_EE=>>\xEE
CHAR_ETEND_EF=>>\xEF
CHAR_ETEND_F0=>>\xF0
CHAR_ETEND_F1=>>\xF1
CHAR_ETEND_F2=>>\xF2
CHAR_ETEND_F3=>>\xF3
CHAR_ETEND_F4=>>\xF4
CHAR_ETEND_F5=>>\xF5
CHAR_ETEND_F6=>>\xF6
CHAR_ETEND_F7=>>\xF7
CHAR_ETEND_F8=>>\xF8
CHAR_ETEND_F9=>>\xF9
CHAR_ETEND_FA=>>\xFA
CHAR_ETEND_FB=>>\xFB
CHAR_ETEND_FC=>>\xFC
CHAR_ETEND_FD=>>\xFD
CHAR_ETEND_FE=>>\xFE
CHAR_ETEND_FF=>>\xFF
```

##### reference.json
** TODO: describe file composition for change if you need/want **

### NOTE
This file (note.json) contains rules for correlation score, you can reduce or inscrease score when you matched multi rules (IOC/REF/SIG).
The json file contains main key 'rules' in value is Array.
Each element array is a Rule. A rule is composed of multi elements:
* 'id' Key : value is a array contains all id which must present in event
* 'optid' Key : value is a array contains all id which maybe present in event
* 'opt_num' Key : value is a integer which indicate number of optionnal id must be present in event. In example below, at least one id between 3 and 4 must be present.
* 'noid' Key : value is a array contains all id which must ** not ** present in event
* 'overwrite' Key : value is boolean, indicate if overwrite score reduce even if actually event score is bigger
** This file is a Json format **
```
{"rules":[
	{"id":[2],"optid":[3,4],"opt_num":1,"noid":[],"note":3,"overwrite":true}
	]
}
```
### FINGERPRINT
The file fingerprint_conf.json contains rules which create fingerprint on event and tag with first or complementary information.
The key of Json is value must present in select_fp (main configuration). The value of key is Hash composed of multi key+value:
* Key 'fields': value contains Array with name of field used for create simhash.
* Key 'delay': use for restart with tag first after delay (utility for dhcp by example). The value is number in second.
* Key 'hashbit': value is number, use for define size of simhash.
** This file is a Json format **
```
{
"squid":{"fields":["src_ip","dst_host","dst_ip","uri_proto","sig_detected_name","ioc_detected","tags"],"delay":36000, "hashbit": 32}
}
```
#### drop-fp.json
Use this file for drop event for false positive by example. The key of json is simhash and value is reason of drop.
** This file is a Json format **
```
{"821861840": "false positive: update of software XXX"}
```
### FREQUENCE
THe file conf_freq.json contains rules for create interne db frequence (restart from zero if you restart logstash).
The first key is rules and value is array which contains rules.
A rule is hash composed of multi element:
* Key 'select_field': value is hash with key field name and value array contais value must present. THis parameter is filter.
* Key 'note': use parameter for set score if rule matched
* Key 'refresh_time': use parameter for give delay between each verify if event increase 
* Key 'reset_time': use paramter for give delai for reset database value (for only this rule)
* Key 'wait_after_reset': time to wait after reset database or first start
* Key 'id': value is number. Use parameter to fix id of rule.
** This file is a Json format **
```
{"rules":[ 
  {"select_field": {"tags":["squid"],"return_code":["404"]}, "note": 2, "refresh_time": 60, "reset_time": 86400, "wait_after_reset": 10, "id": 3001}
]}
```      

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-awesome", :path => "/your/local/logstash-filter-awesome"
```
- Install plugin
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {awesome {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-awesome.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
