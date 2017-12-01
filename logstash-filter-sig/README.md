# Logstash Plugin Filter "SIG"

*Logstash plugin Filter "Sig" can help you to detect security threat in log by differents ways.*

## Features

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

## Require

This plugin use simhash for find around result and futur possibility check and correlation.

**!!!! You must install simhash under logstash, follow instruction:** 

1. curl -sSL https://get.rvm.io | bash && /usr/local/rvm/bin/rvm install 1.9.3-dev
2. IN vendor/jruby/lib/ruby/shared/mkmf.rb add line (45):
  * RbConfig::MAKEFILE_CONFIG["CPPFLAGS"] += ' -I/usr/local/rvm/rubies/ruby-1.9.3-p551-dev/include/ruby-1.9.1/x86_64-linux/'
  * RbConfig::MAKEFILE_CONFIG['includedir'] = "/usr/local/rvm/rubies/ruby-1.9.3-p551-dev/include/ruby-1.9.1/"
3. env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/bundle/jruby/1.9/bin/bundle install
4. env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 JRUBY_OPTS='-Xcext.enabled=true' /usr/share/logstash/vendor/jruby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem build logstash-filter-sig.gemspec
5. /usr/share/logstash/bin/logstash-plugin install logstash-filter-sig-3.0.0.gem 


## Let's start with docker

*DockerFile create contener with last logstash and install plugin: sig, enrsig and fir. If you add others plugins, please edit Dockerfile before run docker composer*

Enter in directory "docker" and edit file "docker-compose.yml" :
* volumes: change volume source (on host) with your logstash path configuration

Before run docker composer, verify configuration logstash is valid. Verify configuration plugin logstash is valid too (use sample configuration in plugins directory for help you).

Run docker-compose

## Main Configuration (logstash-filter.conf)
**Refresh DB : The plugin use some files configurations, files are reload every hour (default). You can use config/db files with git update...** 

Configuration of each features:
* Disable check features: use for disable feature check
  * no_check => "sig_no_apply_all" : add in event a field name "sig_no_apply_all" for disable all checking
  * disable_drop => false :  if you turn to true, feature "drop" is disable
  * disable_enr => false :  if you turn to true, feature "enrichissement" is disable
  * disable_fp => false :  if you turn to true, feature "fingerprint & drop fingerprint" is disable
  * disable_nv => false :  if you turn to true, feature "new value" is disable
  * disable_bl => false :  if you turn to true, feature "blacklist" is disable
  * disable_ioc => false :  if you turn to true, feature "ioc" is disable
  * disable_sig => false :  if you turn to true, feature "signature" is disable
  * disable_ref => false :  if you turn to true, feature "reference" is disable
  * disable_freq => false :  if you turn to true, feature "frequence" is disable
  * disable_note => false :  if you turn to true, feature "score" is disable

* Drop feature: drop false positive and noise events (used before and after enrichissement feature)
  * noapply_sig_dropdb => "sig_no_apply_dropdb" : add in event a field name "sig_no_apply_dropdb" for disable checking
  * db_drop => "/etc/logstash/db/drop-db.json" : path of file drop-db.json (see below for more information)
  * refresh_interval_dropdb => 3600 : delay interval (in second) to reload db_drop

* Enrichissement feature: Enrichissement event with database or/and send event to plugin enrsig for enrich event by active method (whois, ssl_check, nmap, ...)
  * noapply_sig_enr => "sig_no_apply_enr" : add in event a field name "sig_no_apply_enr" for disable checking
  * conf_enr => "/etc/logstash/db/enr.json" : path of file enr.json (see below for more information)
  * refresh_interval_enr => 3600 : delay interval (in second) to reload "enr"
  * field_enr => "request_enrichiment": field name where to add ask for logstash enrsig plugin (active check).
  * enr_tag_response => "ENR_RETURN_TO_JOHN": add tag to event for identify who is origin of resquest, and resend the result to good server
  
* New value feature : check new value in field
  * conf_nv => "/etc/logstash/db/new.json" : path of file new.json (see below for more information)
  * db_nv => "/etc/logstash/db/new-save.json" : path of file new-save.json (see below for more information)
  * noapply_sig_nv => "sig_no_apply_nv" : add in event a field name "sig_no_apply_nv" for disable checking
  * refresh_interval_confnv => 3600 : delay interval (in second) to reaload "conf_nv"
  * save_interval_dbnv => 3600 : delay interval (in second) to save "db_nv"
  * target_nv => "new_value_" : prefix value of name field created if new value detected
  
* BL (Black list) REPUTATION feature: check ip reputation
  * conf_bl => "/etc/logstash/db/bl_conf.json" : path of file bl_conf.json (see below for more information)
  * file_bl => [Array type] ["/etc/logstash/db/firehol_level1.netset","/etc/logstash/db/firehol_level2.netset","/etc/logstash/db/firehol_level3.netset","/etc/logstash/db/firehol_level4.netset","/etc/logstash/db/firehol_webserver.netset","/etc/logstash/db/firehol_webclient.netset","/etc/logstash/db/firehol_abusers_30d.netset","/etc/logstash/db/firehol_anonymous.netset","/etc/logstash/db/firehol_proxies.netset"] : path of files contains ip reputation
    * You can use firehol BL: https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webserver.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_30d.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset,https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset
  * noapply_sig_bl => "sig_no_apply_bl" : add in event a field name "sig_no_apply_bl" for disable checking
  * refresh_interval_confbl => 3600 : delay interval (in second) to reload conf_bl & db_bl (file bl)
  * targetname_bl => "bl_detected_category" : field name to save value of category if ip reputation found

* IOC feature: check IOC (IP/URL/HASH/EMAIL/ ...)
  * db_ioc => ["/etc/logstash/db/ioc.json", "/etc/logstash/db/ioc_local.json"] : Array contains path of files db (ioc_local.json => created by signature function [file_save_localioc], ioc.json) (see below for more information)
  * conf_ioc => "/etc/logstash/db/ioc_conf.json" : path of file ioc_conf.json (see below for more information)
  * target_ioc => "ioc_detected" : name of field where you save detected IOC
  * targetnum_ioc => "ioc_detected_count" : name of field where you save count of detected IOC
  * targetname_ioc => "ioc_detected_name" : name of field where you save detected IOC name
  * refresh_interval_dbioc => 3600 : delay interval (in second) to reload conf_ioc & db_ioc
  * noapply_ioc => "sig_no_apply_ioc" : add in event a field name "sig_no_apply_ioc" for disable checking
  
* Signature feature: check signatures
  * conf_rules_sig => "/etc/logstash/db/sig.json" : path of file sig.json (see below for more information)
  * file_save_localioc => "/etc/logstash/db/ioc_local.json" : path of file ioc_local.json (see below for more information)
  * target_sig => "sig_detected" : name of field where you save Rules detected
  * targetnum_sig => "sig_detected_count" : name of field where you save count of rules detected
  * targetname_sig => "sig_detected_name" : name of field where you save name of rules detected
  * refresh_interval_confrules => 3600 : delay interval (in second) to refresh file_save_localioc & conf_rules_sig
  * noapply_sig_rules => "sig_no_apply_rules" : add in event a field name "sig_no_apply_rules" for disable checking
  * check_stop => false : turn to true if you want stop checking after first found
  
* REFERENCE (old ANOMALIE) feature: Check event by compare with reference data
  * conf_ref => "/etc/logstash/db/conf_ref.json" : path of file conf_ref.json (see below for more information)
  * db_ref => "/etc/logstash/db/reference.json" : path of file reference.json (see below for more information)
  * db_pattern => "/etc/logstash/db/pattern.db" : path of file pattern.db (see below for more information)
  * refresh_interval_dbref => 3600 : delay interval (in second) to reload db_ref & db_pattern & conf_ref
  * noapply_ref => "sig_no_apply_ref" : add in event a field name "sig_no_apply_ref" for disable checking
  * target_ref => "ref_detected" : name of field where you save detected differences between event and reference
  * targetnum_ref => "ref_detected_count" : name of field where you save count detected differences between event and reference
  * targetname_ref => "ref_detected_name" : name of field where you save detected name of difference between event and reference
  * ref_aroundfloat => 0.5 : round the score if not integer (float result)
  * ref_stop_after_firstffind => true : turn to false if you want continue to checking after first difference found
  
* Score feature: change value of score if event is matched by several features
  * targetnote => "sig_detected_note" : name of field where you saved score provieded by features: IOC/SIG/REF/BL...
  * targetid => "sig_detected_id" : name of field where you saved ID rule provieded by features: IOC/SIG/REF/BL...
  * conf_rules_note => "/etc/logstash/db/note.json" : path of file note.json (see below for more information)
  
* Fingerprint feature: Limit alert sent. When first detected, make fingerprint value and tag 'first'. After all others events with same fingerprint is tagged 'info' (information complementary).
  * noapply_sig_dropfp => "sig_no_apply_dropfp" : add in event a field name "sig_no_apply_dropfp" for disable checking
  * conf_fp => "/etc/logstash/db/fingerprint_conf.json" : path of file fingerprint_conf.json (see below for more information)
  * db_dropfp => "/etc/logstash/db/drop-fp.json" : path of file drop-fp.json (see below for more information)
  * select_fp => "tags" : name field for select/filter type event, relationship with fingerprint_conf.json. Exemple: event['tags']="squid" --> (fingerprint_conf.json->>) {"squid":{"fields":[....],...}}
  * target_fp => "fingerprint" : name field where you save fingerprint value
  * tag_name_first => "first_alert" : tag value for first event alert
  * tag_name_after => "info_comp" : tag value for everything after the first alert
  * target_tag_fp => "tags" : field name where you save tag value
  * refresh_interval_conffp => 3600 : delay interval (in second) to reload db_dropfp and conf_fp

* FREQUENCE feature: detect anormaly frequence increase on event flux
  * conf_freq => "/etc/logstash/db/conf_freq.json" : path of file conf_freq.json (see below for more information)
  * refresh_interval_freqrules => 3600 : delay interval (in second) to reload conf_freq
  * noapply_freq => "sig_no_apply_freq" : add in event a field name "sig_no_apply_freq" for disable checking
  
## Files Configuration
**Check in folder conf-samples and scripts-create-db**

### DROP Feature
#### drop-db.json
The file drop-db.json contains rule for drop noise/false positive event.

```json
{"dst_domain": "^google.com$|^mydomain.ext$", "dst_ip": "10.0.0.\\d+"}
```

This configuration drop all event with 'dst_domain' to 'google.com' or 'mydomain.ext', as 'dst-ip' to '10.0.0.0/24'.

The json key is field name to check in event (event['field']), and the value is a regexp to check on field. If regexp matched then event is dropped.

### Enrichissement feature
#### enr.json

You have 2 choices:
 - Use database local (passive enrichissement)
 - Use active enrichissement (command, whois, ssl check, ...) with enrsig. Use enrsig on other server for avoid slow down. In global configuration, if field "enr_tag_response" or "field_enr" exist then pass direct to output and send event to server enrsig. This one resend event to you with result in your input logstash.
```json
{"1": 
	{
		"file":"/etc/logstash/db/whois.json",
		"db": {},
		"prefix": "whois_info_", "filters": {"type": "squid", "src_ip": "^192\\.168\\.0\\.\\\\d+$"}, "link": ["domain_dst"], "if_empty": "WHOIS", "form_in_db": "$1$", "filter_insert": [], "filter_noinsert": []
	}
}
```

This configuration have one rule with ID "1". This rule load local database (whois.json) in db key. 
If event match to "filters" (type == squid and src_ip field matched on regexp "^192\\.168\\.0\\.\\\\d+$") then check in "db": if value contained in "link" name field exist (value of event['domain_dst'] exist in "db") then add information in event field with "prefix"("whois_info_").
                                                                                                          else send request to enrsig plugin (use globale config logstash to redirect request to server logstash with enrsig plugin).
                                                  
### New Value feature
#### new-save.json
The file is auto generated by plugin, but you create file with contains '{}' before run plugin for first time. 
The plugin save information extracted in this file and can reload after restart.

If you want restart at begin, just remove file and recreate json empty '{}'.

#### new.json
The file contains a key "rules", value indicate selected fields for check new values.


```json
{"rules": ["dst_host","user_agent"]}
```
This configuration check new value on field "dst_host" and  "user_agent".

### IP REPUTATION
#### bl_conf.json
The first key of json indicates field selected to check ip reputation list (give path of each files db in 'dbs').

```json
{"fieldx": {'dbs':[file_name,file_name2,...], id: '180XX', 'note': 1, 'category': "malware"}}
```
* ID must be unique (ID of rule). 
* Note (score): between 1 and 4.
* Category: indicate category contained in dbs files (malware, webserveur attack, proxies, ...)
* dbs: contains path of file db (must be too in main conf 'file_bl' in "logstash-filter.conf")

### IOC
#### ioc_conf.json
This file contains rules to check IOC in event.

Whole of rules is hash, one type IOC (ex: URL) is configured by 4 keys:
* First: Key is IOC name in DB, and value is name of field in event to check IOC
  * ex: "ioc_hostname":["_host"] => check IOC hostname on field name *_host* (wildcard indicate all field name contains '_host' by exemple event['dst_hostname'] are checked)
* Second: Key is same name than first key with '_downcase' at end, it's value can be true or false. True verify IOC without case (AbC == abc) and False opposite (AbC != abc)
* Third: key is same name than first key with 'iocnote' at end, it's value is score if IOC detected.
* Fourth key is same name than first key with 'iocid' at end, it's value is ID of rule for use after in SCORE feature by example.

```json
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
This file is generated by plugin by featuring signature with parameter 'extract'.
**Before start for irst time, you create file empty (echo '{}' > ioc_local.json)** 

#### Script to generate ioc.json
Use script ioc_create.sh for generate ioc.json file (in path: "/etc/logstash/db/") from MISP database.
**Require Pymisp (https://github.com/MISP/PyMISP), wget (for download alexa db), misp2json4ioc.py (include in folder scripts), blacklist.json (include in conf-samples)**

##### blacklist.json
Drop IOC that trigger false positive.

```json
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
#### sig.json
The sig.json file contains rules of signature to check in event.

The first key name is 'rules', the value is an array contains all signatures.
Each signature is hash format composed of multi key/value:
* Level 1 : all name key at first level is name of Field to check ({fieldX:{},fieldY:{},...})
  * Only one key/value pair must be used to add the signature information. The key/value signature information are: 
    * "id": (Integer) value is unique ID number of signature
    * "name": (String) value is name of signature
    * "type": (Integer 1 or 2) value is 1 if check signature on event without prerequisites, and value is 2 if you check on event only if another signature found before.
    * "note": (Integer) value is score of signature
    * "modeFP": (Boolean) if value is true, and signature matched then event is dropped (false positive mode)
    * "extract": (Hash -- Optional) (ex: {"field": "ioc_x"}) extract value of field indicated in hash key and put value in ioc local database in field 'ioc_X' indicated in configuration "extract".
  * Check frequence & correlation in different event:
    * "freq_field": (Array) value is array contains name of field of event relationship between anoter event 
    * "freq_delay": (Interger / Second) time delay between first event and last event (if freq_count == 3 then first 1 and last 3)
    * "freq_count": (Interger) count of event you must see for match
    * "freq_resettime": (Interger / Second) time to wait for reseach new frequence when you already detected
    * "correlate_change_fieldvalue": (Array) value is fields name, check field indicated and verify if value is different for each event matched
  * Check differents methods
    * "motif": (Array) value is all motifs to check in field selected.
    * "false": (Hash empty) add key "false" with value hash empty for verify than field not exist
    * "regexp": (Array) (ex: ["^\\d+$","..."]) value is contains regexp, each regexp must be match for valid check. 
    * "notregexp": (Array) value is contains regex, no regexp musn't be match for valid check.
    * "date": (Hash) (syntax: {'egal'|'inf'|'sup'|'diff': x in second}) value contains operator and time in second, check if date is (time.now)-value of time is validate by operator (<,>,!=,==) 
    * "hour":  (Hash) (syntax: {'egal'|'inf'|'sup'|'diff': 0 to 23}) value contains operator and hour range, check if current hour is valid operator (<,>,!=,==) compared to hour indicated
    * "day": (Hash) (syntax: {'egal'|'inf'|'sup'|'diff': 0 to 6}) value contains operator and day range, check if current day is day of value with operator (<,>,!=,==) compared to day indicated
    * "ipaddr": (Hash) (syntax: {'egal'|'diff']: ipaddr or subnet}) value contains operator and ipaddr range, check if ipaddr in field event is valid operator (equalf or different) compared to ipaddr range indicated
    * "sizeope" : (Hash) (syntax: {['egal'|'inf'|'sup'|'diff']: x}) value contains operator and length(x), check size of string contained in field selected, and compare according by operator selected with the value length.
    * "numop" : (Hash) (syntax: {['egal'|'inf'|'sup'|'diff']: x}) value contains operator and integer value (x), check interger contained in field selected, and compare according by operator selected with the integer value.
    * "compope": (Hash) (syntax: {"fieldz": {['egal'|'inf'|'sup'|'diff']: nil}}) value contains other name field compare, operator, compare field and fieldz and check operator if valid.

```json
{"rules":[
	{"type":{"motif":["squid"],"type":1,"note":1,"name":"Field User-AGENT not present","id":1},"user_agent":{"false":{}}},
        {"new_value_dst_host":{"sizeope":{"sup":1},"type":1,"note":1,"name":"New value dst_host","id":2},"type":{"motif":["squid"]}},
	{"elapsed_time":{"numope":{"sup":900000},"type":1,"note":2,"name":"Connection time too long > 15minutes","id":3}},
	{"type":{"motif":["squid"],"type":2,"note":2,"name":"Referer FIELD not present","id":4},"uri_proto":{"notregexp":["tunnel"]},"referer_host":{"false":{}}}
]}
```

### REFERENCE (OLD ANOMALIE)
#### conf_ref.json
The conf_ref.json file contains rules to compare event and reference database.

The first key name is 'rules', the value is an array contains all rule.
Run script for generate reference database before use this feature (**when you generate database reference use clean data or/and verify configuration generated!!**).
A rule is composed of several pair of key/value:
* Key "pivot_field" : filter for select event to check
  * value is a hash with key as field name and value is an array contains value present in event field selected.
* Key "list_sig" : value is an array contains all fields name selected for compare with reference database. If some fields not present in some case, it's doesn't matter. 
* Key "relation_min" : value is integer, verify than relationship simhash exist and is supperior to "relation_min".
* Key "simhash_size" : value is integer, make size of simhash... (change according by data size to simhash)
* Key "simhash_use_size" (Not works, i will work on!)
* Key "id" : valud is ID of rule

```json
{"rules":[ 
  {"pivot_field":{"tags":["squid"]}, "list_sig": ["src_host","src_ip","dst_host","dst_ip","uri_proto","uri_global"], "relation_min": 10, "simhash_size": 32, "simhash_use_size": 32, "id": 2001}
]}
```

#### Create reference database (reference.json)
Generate database reference (reference.json file) with script include in scripts folder.
Run script with syntaxe: ./create.rb conf_ref.json pattern.db  https://user:secret@localhost:9200
For make good databases, use elasticsearch contains clean data log and verify database for change strange value.

##### note_ref_defaut.json
This file contains score by default for each rule matched.
The names keys contains suffix "NOTE" and name of verification method, the value fix note for method matched.
Only a key is different, "NOTE_UNIQ_REDUC" can reduce score when event is "unique". By example if matched LEN method and if "uniq" matched then score value is not 0.25 but 0.25-0.1 => 0.15 (according by configuration below).

```json
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

This file contains regexp for check format of field value.

```json
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
This file is generated by script on clean data Elasticsearch.

### NOTE
#### note.json
This file (note.json) contains rules for correlation score, you can reduce or inscrease score when you matched several features (IOC/REF/SIG).
The json file contains main key 'rules' and value is an array contains each rule in hash format.
key/value of hash Rule are:
* 'id' Key : value is a array contains all "ID" matched in event
* 'optid' Key : value is a array contains all "ID" maybe matched in event
* 'opt_num' Key : value is a integer indicate count of 'optid' must be present in event. In example below, at least one ID, 3 or 4 must be present.
* 'noid' Key : value is a array contains all ID musn't be present in event
* 'overwrite' Key : value is boolean, indicate if you can overwrite score for reduce.

```json
{"rules":[
	{"id":[2],"optid":[3,4],"opt_num":1,"noid":[],"note":3,"overwrite":true}
	]
}
```

### FINGERPRINT
#### fingerprint_conf.json
The file fingerprint_conf.json contains rules for create fingerprint, and tag "first" or "complementary information" in event.
The first key is value must be present in select_fp (main configuration). The value of key is Hash composed with key/value:
* Key 'fields': value is array contains name of field used for create simhash.
* Key 'delay': reset all fingerprint for "fields" after time exceeded (use for dhcp by example). The value is second number.
* Key 'hashbit': value is number, define size of simhash.

```json
{
"squid":{"fields":["src_ip","dst_host","dst_ip","uri_proto","sig_detected_name","ioc_detected","tags"],"delay":36000, "hashbit": 32}
}
```

#### drop-fp.json
Drop false positive event. The key of json is simhash and value is reason of drop.

```json
{"821861840": "false positive: update of software XXX"}
```

### FREQUENCE
#### conf_freq.json
The file conf_freq.json contains rules for create interne db frequence (reset if you restart logstash).
The first key is rules and value is array which contains each rule in hash format.
A rule is hash composed of key/value:
* Key 'select_field': value is hash, key is field in event and value is an array contains value must be present in event field. This parameter is filter for selected event to check.
* Key 'note': score of rule
* Key 'refresh_time': parameter give delay check (event increase?)
* Key 'reset_time': paramter give delay for reset database value (for only this rule)
* Key 'wait_after_reset': time to wait after reset database or first start
* Key 'id': value is number. ID of rule

```json
{"rules":[ 
  {"select_field": {"tags":["squid"],"return_code":["404"]}, "note": 2, "refresh_time": 60, "reset_time": 86400, "wait_after_reset": 10, "id": 3001}
]}
```      

## Contributing


** You welcome to contribute (report bug, new functionality, ...)! **

** Possibility you meet bug, I recently ported on logstash 5.x !! ** 

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Contact
Lionel PRAT lionel.prat9 (at) gmail.com or cronos56 (at) yahoo.com
