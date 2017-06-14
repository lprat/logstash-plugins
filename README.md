# My logstash-plugins for help in your security log search (next of SIEM but miss post correlate and another possibility)

## logstash-filter-sig
Logstash plugin Filter "Sig" can help you to detect security threat in log by differents techniques:
* Drop False positive and noise
* IOC extracted of MISP by exemple
* Find new value in field
* SIG with some fonctionnality search
  * Each rule have:
    * a name: name of rule for report
    * a id: id use for correlate and change note
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
      * use for correlate multi source with field value common (ex: ip) on events but different event type (squid and antivirus) (ex: sig type one error/detect on each type)
    * Check frequence on event second possibility use for correlate
* By databases of reference (before make with ES data contains clean logs -- script include) (new version of my project AEE [https://github.com/lprat/AEE])
  * Check size, check regexp data, uniq value (ex: uniq value can be @timestamp because change everytime)    
  * Check link/relationship between not uniq (value) fields (idea inspired by tool PicViz). Exemple on apache log page test.php return always 200 in all logs. The link/relationship value/field is "uri_page(test.php)<->return_code(200)"
* Note/Score functionnality for change score (up or down) of alert with correlate IOC/multi SIG/REF match
* By frequence but create alert not defined reason, just know log loading up and not normaly. You can select frequence on specifique event by filters

## logstash-filter-ensig
Logstash plugin Filter "EnrSig" can help you to enrich event with different sources informations. It use system command with arguments for enrich event.

## logstash-output-fir
Logstash plugin Output for send alert (created by filter sig) in FIR (Cert SG - https://github.com/certsocietegenerale/FIR) 

## Architecture sample
![alt text](https://github.com/lprat/logstash-plugins/raw/master/sample-architecture/Architecture-sample.png "Architecture sample")
![alt text](https://github.com/lprat/logstash-plugins/raw/master/sample-architecture/Diagramme-archi.png "Diagramme architecture sample")

## Contact

@ lionel.prat9 (at) gmail.com Ou cronos56 (at) yahoo.com

