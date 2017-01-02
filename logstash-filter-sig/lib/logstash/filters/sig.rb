# encoding: utf-8
# Filter "SIG" analyze signature regexp with condition
# POC on event normalized -- experimental version
# Contact: Lionel PRAT (lionel.prat9@gmail.com)

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "simhash"
require 'digest'
require "openssl"
require 'ipaddr'
require 'time'

#TODO fix fingerprint must be used when SIG/REF/IOC detected
#plugin multi function:
# - signature 
# - IOC
# - ANOMALIE
# - new value in time or no time
# - fingerprint simhash
# - filter false positive
# - first drop list on fingerprint or field -> regexp (ex: host & domain)
# Optimiz

#TODO: SIG add tag on sig for FIR

class LogStash::Filters::Sig < LogStash::Filters::Base
  config_name "sig"
  milestone 1
  ############PLUGIN LOGSTASH SIG -- lionel.prat9@gmail.com #############
  ############MULTI FUNCTIONNALITY IN ORDER CALL########################
  ###### DROP_FIRST[FIELD(regexp_list)]->NEW_VALUE[time/notime]->SIG[FIELD_IOC(misp_extract),RULES(list),FALSE_POSITIVE(drop),ANOMALIE(db_reference),DROP_END[SIMHASH(match_list)],FREQ(db_frequence -> create new event if alert) ########
  ###### SIG add special_tag if match #######
  ############### CONFIG DROP SIMPLE FIRST & FINGERPRINT SIMHASH ###################
  ## DESCRIPTION: use for drop noise without risk with very simple rule, if nothing detected then create fingerprint simhash, thus check if fingerprint content in db fingerprint false positive to drop.
  ##              Fingerprint hash can use by active add information (scan active, whois, ssl check, ...) for avoid to verify multi time for same alert.
  ## EXAMPLE: { "domain" : "^google.(com|fr)$"}
  #disable by field in event
  config :no_check, :validate => :string, :default => "sig_no_apply_all"
  #disable functions
  config :disable_drop, :validate => :boolean, :default => false
  config :disable_fp, :validate => :boolean, :default => false
  config :disable_nv, :validate => :boolean, :default => false
  config :disable_ioc, :validate => :boolean, :default => false
  config :disable_sig, :validate => :boolean, :default => false
  config :disable_ref, :validate => :boolean, :default => false
  config :disable_freq, :validate => :boolean, :default => false
  config :disable_note, :validate => :boolean, :default => false
  
  #if field exist in event then no apply drop & fingerprint
  config :noapply_sig_dropfp, :validate => :string, :default => "sig_no_apply_dropfp"
  config :noapply_sig_dropdb, :validate => :string, :default => "sig_no_apply_dropdb"
  
  
  #CONF FINGERPRINT - format: json {"type": {fields: [a,b,c], delay: 3600, hashbit: 16},}
  # create simhash (on hashbit) with fields [a,b,c] for delay 3600 . The delay is used for tag first alert or complementary information. Use delay by exemple if you use dhcp and ip in fingerprint...
  config :conf_fp, :validate => :string, :default => "/etc/logstash/db/fingerprint_conf.json"
  
  #DROP RULES DB - format: json {"field": "regexp"} - don't use same field name more time
  config :db_drop, :validate => :string, :default => "/etc/logstash/db/drop-db.json"
  #DROP FINGERPRINT DB - format: json {"fingerprint": "raison of fp"}
  config :db_dropfp, :validate => :string, :default => "/etc/logstash/db/drop-fp.json"
  
  #Name of field for select rules fp - exemple event['tags']="squid" -- in fp_conf.sig: #{"squid":{"fields":["src_ip","dst_host","dst_ip","uri_proto","sig_detected_name","ioc_detected","tags"],"hashbit":8,"delay":3600}}
  #                                                    |-->   ^^^^^                        ^^^^^  
  config :select_fp, :validate => :string, :default => "tags"
  #Name of field to save fingerprint
  config :target_fp, :validate => :string, :default => "fingerprint"
  
  # add tage name if not match
  # tag mark for difference first fingerprint see, another fingerprint identical is tagger with tag_name_after (complementary information)
  config :tag_name_first, :validate => :string, :default => "first_alert"
  config :tag_name_after, :validate => :string, :default => "info_comp"
  #Select field for write tag information fp: first or complementary
  config :target_tag_fp, :validate => :string, :default => "tags"
  
  #interval to refresh conf fingerprint & db
  config :refresh_interval_conffp, :validate => :number, :default => 3600
  #interval to refresh database rules & fingerprint
  config :refresh_interval_dropdb, :validate => :number, :default => 3600
  
  ############### CONFIG NEW VALUE ###################
  #Description: check by rule if event is new and tag event
  #Exemple: verify on field domain new value, if field domain in event content new value then add in db and tag event
  
  #File config - format: json {"rules": ["fieldy","fieldx"]}
  config :conf_nv, :validate => :string, :default => "/etc/logstash/db/new.json"

  #File save db - format: json
  config :db_nv, :validate => :string, :default => "/etc/logstash/db/new-save.json"

  #if field exist in event then no apply new value tag
  config :noapply_sig_nv, :validate => :string, :default => "sig_no_apply_nv"
  
  #interval to refresh conf new_value
  config :refresh_interval_confnv, :validate => :number, :default => 3600
  
  #interval to save file db new value
  config :save_interval_dbnv, :validate => :number, :default => 3600
  
  #Name of prefix field to save new_value tag (prefix+field_name)
  config :target_nv, :validate => :string, :default => "new_value_"
  
  ############### CONFIG SIG BASE ###################
  #numeric test: R[1]['champs0']['numope']['egal'|'inf'|'sup'|'diff']=numeric_value
  #format file SIG JSON example: {"rules":[{"field2":{"motif":["mot1","mot2"],"note":5, "name":"test", "type":1, "id": 1, "extract": {'field': 'ioc_field'}},"field3":{"false":{}},"field1":{"regexp":["/update\\\?id\=[-0-9A-Fa-f]{8}","/[0-9A-F]{8}/[0-9A-F]{8}/[0-9A-F]{8}"]}},{"fieldx6":{},"fieldx5":{},"fieldx4":{}}]}
  #R[1]['champs0']['regexp']=[]
  #R[1]['champs1']['notregexp']=[]
  #R[1]['champs2']['motif']=[]
  #R[1]['champs0']['date']['egal'|'inf'|'sup'|'diff']=x  -> (time.now)-x ope value field
  #R[1]['champs0']['hour']['egal'|'inf'|'sup'|'diff']=19 [interger]
  #R[1]['champs0']['day']['egal'|'inf'|'sup'|'diff']=0 (0==sunday,1==monday,...) [Interger]
  #R[1]['champs0']['ipaddr']['egal'|'diff']="192.168.0.0/24"
  #R[1]['champs0']['sizeope']['egal'|'inf'|'sup'|'diff']=0
  #R[1]['champs0']['numope']['egal'|'inf'|'sup'|'diff']=0
  #R[1]['champs0']['compope']['champsX']['egal'|'inf'|'sup'|'diff'] => string(not sup & info for string)
  #R[1]['champs3']['false']
  #R[1]['champs3']['note'] = numeric, add one by rule/sig /* not importance for field use for note, juste one time */
  #R[1]['champs3']['name'] = "SIG_DETECTED_TEST_01" /* not importance for field use for name, juste one time */
  #R[1]['champs3']['type'] = 1 (primary sig -- defaut value) -- 2 (secondary sig -> add if only detect primary sig before)
  #R[1]['champs3']['modeFP'] = true or false (true == delete & false or not present ==  detect)
  #R[1]['champs3']['modeFP'] = true or false (true == delete & false or not present ==  detect)
  # brute force & correlation sig add: "freq_field:" [field,field,field,field],"freq_delay":60s,freq_count: 3, freq_resettime: 3600s, correlate_change_fieldvalue: []
  # use extract on sure alerte without false postive to add IOC in IOC check list in real time
  # extract field value to insert in ioc_field; ex: extract: {'src_ip': 'ioc_ip', 'user_agent': 'ioc_user-agent'}
  #order verify: FIELD, MOTIF, REGEXP
  #At first detected sig, then stop search another sig!!!!
  #File content rules signatures expression in json
  config :conf_rules_sig, :validate => :string, :default => "/etc/logstash/db/sig.json"
  config :file_save_localioc, :validate => :string, :default => "/etc/logstash/db/ioc_local.json"
  #format json -- example:
  #{"rules":[
  #      {"id":[22],"optid":[16,38],"opt_num":1,"noid":[],"note":3,"overwrite":true}
  #]}
  # id: list contains id of rules must present
  # optid & opt_num: list contains if of rules can present with minimum of "opt_num" id present
  #         			exemple: [16,38] with opt_num =1 then if 16 or 38 or (16 and 38) present is match
  # noid: list id of rules must absent
  # overwrite: if overwrite is true, it's significate than if note is more less then defined before, the value is overwrite and note is more less.
  # note: it's value of new note for event match.
  config :conf_rules_note, :validate => :string, :default => "/etc/logstash/db/note.json"
  
  #Name of fields to save value if sig match: name sig, count
  config :target_sig, :validate => :string, :default => "sig_detected"
  config :targetnum_sig, :validate => :string, :default => "sig_detected_count"
  config :targetname_sig, :validate => :string, :default => "sig_detected_name"
  #Interval to refresh conf rules sig
  config :refresh_interval_confrules, :validate => :number, :default => 3600
  
  #if field exist in event then no apply rules check
  config :noapply_sig_rules, :validate => :string, :default => "sig_no_apply_rules"
  
  #stop check at one time find sig
  config :check_stop, :validate => :boolean,  :default => false
  
  #LIST File content IOC - format json - exemple: {"ioc_as":["44050","55960","24961","203973"]}
  config :db_ioc, :validate => :array, :default => ["/etc/logstash/db/ioc.json", "/etc/logstash/db/ioc_local.json"]
  #Rules IOC Conf- format json - exemple get rules from list_field_ioc file: {"ioc_hostname":["_host"], "ioc_hostname_downcase":true, "ioc_hostname_iocnote":1, "ioc_hostname_iocid":1001}
  # conf file significate for ioc_hostname search in value of field name containt string '_host'
  # If ioc_hostname_downcase is true then force downcase value in field
  # ioc_hostname_note give note to event if ioc match
  # ioc_hostname_iocid: give id number to ioc, used in note_sig for change note by relation with another match (sig...). 
  # Ioc ID must be more than 1000 -> 1001..1999
  config :conf_ioc, :validate => :string, :default => "/etc/logstash/db/ioc_conf.json"
  
  #Name of fields to save value if ioc match: name ioc, count
  config :target_ioc, :validate => :string, :default => "ioc_detected"
  config :targetnum_ioc, :validate => :string, :default => "ioc_detected_count"
  config :targetname_ioc, :validate => :string, :default => "ioc_detected_name"
  
  #Name of field where save note of sig & ioc ...
  config :targetnote, :validate => :string, :default => "sig_detected_note"
  config :targetid, :validate => :string, :default => "sig_detected_id"
  
  #Interval to refresh db ioc
  config :refresh_interval_dbioc, :validate => :number, :default => 3600

  #if field exist in event then no apply check ioc
  config :noapply_ioc, :validate => :string, :default => "sig_no_apply_ioc"
  
  ##ANOMALIE
  #Conf ref -- format json -- PIVOT -> SIG -> REF
  # rules[ {"pivot_field":[field1,field2], "list_sig": [fieldx,fieldy,...]} ]
  #list_sig: all field used for sig, if all field not present, it doesn't matter, use field present in event and list_sig
  config :conf_ref, :validate => :string, :default => "/etc/logstash/db/conf_ref.json"
  #DB reference extract of ES by script
  config :db_ref, :validate => :string, :default => "/etc/logstash/db/reference.json"
  #RegExp DB FILE
  config :db_pattern, :validate => :string, :default => "/etc/logstash/db/pattern.db"
  #Interval to refresh db reference
  config :refresh_interval_dbref, :validate => :number, :default => 3600
  #if field exist in event then no apply check ref
  config :noapply_ref, :validate => :string, :default => "sig_no_apply_ref"
  #Name of fields to save value if ref match: name ioc, count
  config :target_ref, :validate => :string, :default => "ref_detected"
  config :targetnum_ref, :validate => :string, :default => "ref_detected_count"
  config :targetname_ref, :validate => :string, :default => "ref_detected_name"
  config :ref_aroundfloat, :default => 0.5 # TODO :validate => :float
  config :ref_stop_after_firstffind, :validate => :boolean, :default => true
  #pivot 1 syslog_programm -> add in ref.json for add multi profil
  #config :sg_extract, :validate => :string, :default => "syslog_program"
  #pivot 2 syslog_pri -> add in ref.json for add multi profil
  #config :spri_extract, :validate => :string, :default => "syslog_pri"
  #exclude field for create sig -> add field list for create sig and add in ref.json
  #config :exclude_create_sig, :validate => :array, :default => ["tags","@source_host","_type","type","@timestamp","@message","@version","_id","_index","_type","host","message","received_at","received_from","syslog_facility","syslog_facility_code","syslog_pri","syslog_pid","syslog_program","syslog_severity_code","syslog_severity"]
  
  ##FREQUENCE
  #rules_freq = [ {'select_field': {'fieldx':[value_list],'fieldy':[value_list]}, 'note': X, 'refresh_time': Xseconds,'reset_time': Xseconds[1j], 'reset_hour': '00:00:00', 'wait_after_reset': 10, 'id': 30XXX},...]
  config :conf_freq, :validate => :string, :default => "/etc/logstash/db/conf_freq.json"
  #Interval to refresh rules frequence
  config :refresh_interval_freqrules, :validate => :number, :default => 3600
  #if field exist in event then no apply check freq
  config :noapply_freq, :validate => :string, :default => "sig_no_apply_freq"  
  #rules_freq = [ {'select_field': {'fieldx':[value_list],'fieldy':[value_list]}, 'note': X, 'refresh_time': Xseconds,'reset_time': Xseconds[1j], 'reset_hour': '00:00:00', 'wait_after_reset': 10, 'id': 30XXX},...]
  #select field for select => first filter
  #select field value => second filter
  #refresh_time for check and calculate all time result: max & variation
  # note if match
  # reset time in second for reset all counter value
  # reset hour for begin reset with hour => use for 24h reset begin at 00:00
  # wait_after_reset: dont't check before 10 times values
  #db_freq = { '30XXX': {'refresh_date': date, 'old_date': date,'num_time': Xtimes, 'V_prev': x/m, 'Varia_avg': z/m, 'count_prev': Xtimes, 'count_cour': Xtimes, 'V_max': x/m, 'Varia_max': x/m, 'Varia_min': +/- x/m, 'Varia_glob': x/m}}
  #check refresh db ref
  public
  def register
    @logger.info("Plugin SIG. Loading conf...")
    #create var extract file db & conf
    @ioc_db = {}
    @ioc_db_local = JSON.parse( IO.read(@file_save_localioc, encoding:'utf-8') ) unless @disable_sig and @disable_ioc #use on sig extract
    @ioc_rules = {}
    @note_db = []
    @sig_db = {}
    @sig_db_array = []
    @sig_db_array_false = []
    @sig_db_array_len = 0
    @nv_db = JSON.parse( IO.read(@db_nv, encoding:'utf-8') ) unless @disable_nv
    @nv_rules = {}
    @fp_rules = {}
    @fp_db = {}
    @drop_db = {}
    @fingerprint_db = {} #temporary db
    @ref_db = {}
    @pattern_db = {}
    @ref_rules = {}
    @freq_rules = {}
    @db_freq = {}
    ###
    ###special DB
    @sig_db_freq = {}
    ###
    #hash file
    @hash_conf_rules_sig = ""
    @hash_conf_rules_note = ""
    @hash_conf_freq = ""
    @hash_conf_fp = ""
    @hash_conf_nv = ""
    @hash_dbioc = {}
    @hash_conf_ioc = ""
    @hash_dbref = ""
    @hash_dbpattern = ""
    @hash_conf_ref = ""
    @hash_dropdb = ""
    @hash_dropfp = ""
    ###
    #load conf & db
    @load_statut = false
    load_conf_rules_sig unless @disable_sig
    load_conf_rules_note unless @disable_sig and @disable_ioc and @disable_ref
    load_conf_fp unless @disable_fp
    load_conf_nv unless @disable_nv
    load_conf_ioc unless @disable_ioc
    load_db_ioc unless @disable_ioc
    load_db_drop unless @disable_drop
    load_db_dropfp unless @disable_fp
    load_db_pattern unless @disable_ref
    load_db_ref unless @disable_ref
    load_rules_freq unless @disable_freq
    @load_statut = true
    @load_statut_rules = true
    @load_statut_fp = true
    @load_statut_nv = true
    @save_statut_nv = true
    @load_statut_ioc = true
    @load_statut_ref = true
    @load_statut_drop = true
    @load_statut_freqrules = true
    @load_statut_note = true
    ###
    @logger.info("finish")
    #next refresh file
    tnow = Time.now
    @next_refresh_dbref = tnow + @refresh_interval_dbref
    @next_refresh_dbioc = tnow + @refresh_interval_dbioc
    @next_refresh_confrules = tnow + @refresh_interval_confrules
    @next_refresh_confnv = tnow + @refresh_interval_confnv
    @next_refresh_dbnv = tnow + @save_interval_dbnv
    @next_refresh_dropdb = tnow + @refresh_interval_dropdb
    @next_refresh_conffp = tnow + @refresh_interval_conffp
    @next_refresh_note = tnow + @refresh_interval_confrules
    @next_refresh_freqrules = tnow + @refresh_interval_freqrules
    ###
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    #check field no_check if present stop search
    return unless event.get(@no_check).nil?
    #get time for refresh
    tnow = Time.now
    
    ######DROP FIRST DB USE######
    #refresh db
    unless @disable_drop
      if @next_refresh_dropdb < tnow
        if @load_statut_drop == true
          @load_statut_drop = false
          load_db_drop
          @next_refresh_dropdb = tnow + @refresh_interval_dropdb
          @load_statut_drop = true
        end
      end
      sleep(1) until @load_statut_drop
    end
    #check if db not empty 
    if not @drop_db.empty? and event.get(@noapply_sig_dropdb).nil? and not @disable_drop
      @drop_db.each do |dkey,dval|
        #search field with name of dkey
        if not event.get(dkey).nil? and event.get(dkey).is_a?(String) and not dval.empty? and event.get(dkey) =~ /#{dval}/
          #key exist and match with regexp
          event.cancel
          return
        end
      end
    end
    #######################
    
    ######New Value USE######
    #reshresh conf & save db
    unless @disable_nv
      if @next_refresh_dbnv < tnow
        if @save_statut_nv == true
          @save_statut_nv = false
          save_db_nv
          @next_refresh_dbnv = tnow + @save_interval_dbnv
          @save_statut_nv = true
        end
      end
      if @next_refresh_confnv < tnow
        if @load_statut_nv == true
          @load_statut_nv = false
          load_conf_nv
          @next_refresh_confnv = tnow + @refresh_interval_confnv
          @load_statut_nv = true
        end
      end
      sleep(1) until @load_statut_nv
    end
    #check if db &conf are not empty + select_fp exist
    if not @nv_rules.empty? and @nv_rules['rules'].is_a?(Array) and not @nv_db.empty? and event.get(@noapply_sig_nv).nil? and not @disable_nv
      #check all rules
      for rule in @nv_rules['rules']
        #if rule exist in event?
        if event.get(rule.to_s)
          #yes
          #event content type Array
          if event.get(rule.to_s).is_a?(Array)
            for elem in event.get(rule.to_s)
              if elem.is_a?(String) or elem.is_a?(Numeric)
                if not @nv_db[rule.to_s].include?(elem)
                  #new value => add
                  @nv_db[rule.to_s].push(*elem)
                  event.set(@target_nv+rule.to_s, elem.to_s)
                end
              end
            end   
          #event content type String or Numeric        
          elsif event.get(rule.to_s).is_a?(String) or event.get(rule.to_s).is_a?(Numeric) 
            if not @nv_db[rule.to_s].include?(event.get(rule.to_s))
              #new value => add
              @nv_db[rule.to_s].push(*event.get(rule.to_s))
              event.set(@target_nv+rule.to_s, event.get(rule.to_s).to_s)
            end
          end
        end
      end
    end
    #########################
    
    ######IOC SEARCH######
    #refresh db
    unless @disable_ioc
      if @next_refresh_dbioc < tnow
        if @load_statut_ioc == true
          @load_statut_ioc = false
          load_conf_ioc
          load_db_ioc
          @next_refresh_dbioc = tnow + @refresh_interval_dbioc
          @load_statut_ioc = true
        end
      end
      sleep(1) until @load_statut_ioc
    end
    #check db not empty
    if not @ioc_rules.empty? and not @ioc_db.empty? and event.get(@noapply_ioc).nil? and not @disable_ioc
      detected_ioc = Array.new
      detected_ioc_count = 0
      detected_ioc_name = Array.new
      detected_ioc_id = Array.new
      detected_ioc_note = 0
      #verify ioc by rules
      @ioc_rules.each do |rkey,rval|
        if rval.is_a?(Array) and not rkey =~ /_downcase$|_iocnote$|_iocid$/ and @ioc_db[rkey.to_s]
          list_search = []
          #create list value by rule to check ioc
          for elemvalue in rval
            #Collect value of field name contains "elemvalue"
            hash_tmp = event.to_hash.select{|k,v| (k.to_s).include? elemvalue }
            if hash_tmp.values.any?
            #hash not empty
              if list_search.empty?
                if @ioc_rules[rkey+'_downcase'] 
                  #case compare by downcase
                  list_search = hash_tmp.values.map!(&:downcase)
                else
                  #case normaly compare
                  list_search = hash_tmp.values
                end
              else
                if @ioc_rules[rkey+'_downcase'] 
                  #case compare by downcase
                  list_search = list_search + hash_tmp.values.map!(&:downcase)
                else
                  #case normaly compare
                  list_search = list_search + hash_tmp.values
                end
              end
            end
          end
          #compare list_value extract of event for one case of ioc and db_ioc -- intersection
          inter=list_search & @ioc_db[rkey.to_s]
          if inter.any?
            #value(s) find
            ioc_add = {rkey.to_s => inter}
            detected_ioc_name.push(*rkey.to_s)
            detected_ioc.push(*ioc_add)
            detected_ioc_count = detected_ioc_count + 1
            detected_ioc_id.push(*@ioc_rules[rkey+'_iocid'])
            if detected_ioc_note < @ioc_rules[rkey+'_iocnote']
              detected_ioc_note = @ioc_rules[rkey+'_iocnote']
            end
            ioc_add.clear
          end
        end
        #check if ioc find
        if detected_ioc.any?
          #ioc find, add information in event (count, name, id, note)
          unless event.get(@target_ioc).nil?
            event.set(@target_ioc, event.get(@target_ioc) + detected_ioc)
          else
            event.set(@target_ioc, detected_ioc)
          end
          unless event.get(@targetnum_ioc).nil?
            event.set(@targetnum_ioc, event.get(@targetnum_ioc) + detected_ioc_count)
          else
            event.set(@targetnum_ioc, detected_ioc_count)
          end
          unless event.get(@targetname_ioc).nil?
            event.set(@targetname_ioc, event.get(@targetname_ioc) + detected_ioc_name)
          else
            event.set(@targetname_ioc, detected_ioc_name)
          end
          unless event.get(@targetid).nil?
            event.set(@targetid, event.get(@targetid) + detected_ioc_id)
          else
            event.set(@targetid, detected_ioc_id)
          end
          unless event.get(@targetnote).nil?
            if event.get(@targetnote) < detected_ioc_note
              event.set(@targetnote, detected_ioc_note)
            end
          else
            event.set(@targetnote, detected_ioc_note)
          end
        end
      end
    end
    ######################
    
    ######SIG SEARCH######
    unless @disable_sig
      if @next_refresh_confrules < tnow
        if @load_statut_rules == true
          @load_statut_rules = false
          load_conf_rules_sig
          save_db_ioclocal
          clean_db_sigfreq(tnow)
          @next_refresh_confrules = tnow + @refresh_interval_confrules
          @load_statut_rules = true
        end
      end
      sleep(1) until @load_statut_rules
    end
    if not @sig_db.empty? and event.get(@noapply_sig_rules).nil? and not @disable_sig
      #create var local for all rules check
      detected_sig = Array.new
      detected_sig_name = Array.new
      detected_sig_count = 0
      detected_sig_note = 0
      detected_sig_id = Array.new
      detected_sig_id_corre = Array.new
      detected_extract = Array.new
      type_sig = 0
      type_obl = 0
      # get list of all name field present in event
      eventK = event.to_hash.keys
      #check all rules
      (0..@sig_db_array_len).each do |i|
        #verify exist field used in rule
        verif=@sig_db_array[i].length
        inter=@sig_db_array[i] & eventK
        if inter.length == verif
          #OK all field rule are present
          #verify if field name exclude by rule are present
          inter=@sig_db_array_false[i] & eventK
          if inter.length == 0
            #OK exclude field are not present in event
            #create variable local by rule
            validfield=0
            #length of field check contains in rule
            countfield=@sig_db_array[i].length
            sig_add = {"Rules" => "Detected rule at emplacement: #{i} (not id)"}
            sig_add["note"] = 0
            #check rule field by field in event
            for kfield in @sig_db_array[i]
              #CHECK SIG BY FIELD BEGIN
              #check_sig used for know if check result step by step for break if not match rules
              check_sig=true
              #BEGIN : CHECK BY MOTIF
              unless @sig_db['rules'][i][kfield]['motif'].nil?
                check_sig=false
                if event.get(kfield).is_a?(Array)
                  l_tmp = event.get(kfield).flatten(10)
                  inter = l_tmp & @sig_db['rules'][i][kfield]['motif']
                  if inter.length != 0
                    sig_add[kfield.to_s]="motif found: #{inter}"
                    check_sig=true
                  end
                elsif @sig_db['rules'][i][kfield]['motif'].include? event.get(kfield)
                  sig_add[kfield.to_s]="motif found #{event.get(kfield)}"
                  check_sig=true
                end
              end
              break if check_sig == false
              #END : CHECK BY MOTIF
              #BEGIN : CHECK BY Compare value of two fields
              unless @sig_db['rules'][i][kfield]['compope'].nil?
                @sig_db['rules'][i][kfield]['compope'].each do |xk,xval|
                  if event.get(xk)
                    if event.get(xk).is_a?(Numeric)
                      unless @sig_db['rules'][i][kfield]['compope'][xk].nil?
                        if event.get(kfield).is_a?(Numeric)
                          unless @sig_db['rules'][i][kfield]['compope'][xk]['egal'].nil?
                            check_sig=false
                            if event.get(kfield) == event.get(xk)
                              sig_add[kfield.to_s]="Fields Value numeric  #{event.get(kfield)} == #{event.get(xk)} found"
                              check_sig=true
                            end
                          end
                          break if check_sig == false
                          unless @sig_db['rules'][i][kfield]['compope'][xk]['sup'].nil?
                            check_sig=false
                            if event.get(kfield) > event.get(xk)
                              sig_add[kfield.to_s]="Fields Value numeric  #{event.get(kfield)} > #{event.get(xk)} found"
                              check_sig=true
                            end
                          end
                          break if check_sig == false
                          unless @sig_db['rules'][i][kfield]['compope'][xk]['inf'].nil?
                            check_sig=false
                            if event.get(kfield) < event.get(xk)
                              sig_add[kfield.to_s]="Fields Value numeric  #{event.get(kfield)} < #{event.get(xk)} found"
                              check_sig=true
                            end
                          end
                          break if check_sig == false
                          unless @sig_db['rules'][i][kfield]['compope'][xk]['diff'].nil?
                            check_sig=false
                            if event.get(kfield) != event.get(xk)
                              sig_add[kfield.to_s]="Fields Value numeric  #{event.get(kfield)} != #{event.get(xk)} found"
                              check_sig=true
                            end
                          end
                          break if check_sig == false
                        end
                      end
                    elsif event.get(xk).is_a?(String)
                      unless @sig_db['rules'][i][kfield]['compope'][xk].nil?
                        if event.get(kfield).is_a?(String)
                          unless @sig_db['rules'][i][kfield]['compope'][xk]['egal'].nil?
                            check_sig=false
                            if event.get(kfield).eql?(event.get(xk))
                              sig_add[kfield.to_s]="Fields Value String  #{event.get(kfield)} == #{event.get(xk)} found"
                              check_sig=true
                            end
                          end
                          break if check_sig == false
                          unless @sig_db['rules'][i][kfield]['compope'][xk]['diff'].nil?
                            check_sig=false
                            if not event.get(kfield).eql?(event.get(xk))
                              sig_add[kfield.to_s]="Fields Value String  #{event.get(kfield)} != #{event.get(xk)} found"
                              check_sig=true
                            end
                          end
                          break if check_sig == false
                        end
                      end
                    #add elsif event.get(kfield).is_a?(Array) ?
                    end
                  end
                end
              end
              break if check_sig == false
              #END : CHECK BY Compare value of two fields
              #BEGIN : CHECK BY numeric operation
              unless @sig_db['rules'][i][kfield]['numope'].nil?
                if event.get(kfield).is_a?(Numeric)
                  unless @sig_db['rules'][i][kfield]['numope']['egal'].nil?
                    check_sig=false
                    if event.get(kfield) == @sig_db['rules'][i][kfield]['numope']['egal']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield)} == #{@sig_db['rules'][i][kfield]['numope']['egal']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['numope']['sup'].nil?
                    check_sig=false
                    if event.get(kfield) > @sig_db['rules'][i][kfield]['numope']['sup']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield)} > #{@sig_db['rules'][i][kfield]['numope']['sup']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['numope']['inf'].nil?
                    check_sig=false
                    if event.get(kfield) < @sig_db['rules'][i][kfield]['numope']['inf']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield)} < #{@sig_db['rules'][i][kfield]['numope']['inf']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['numope']['diff'].nil?
                    check_sig=false
                    if event.get(kfield) != @sig_db['rules'][i][kfield]['numope']['diff']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['numope']['diff']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                end
              end
              #END : CHECK BY numeric operation
              #BEGIN : CHECK BY date
              unless @sig_db['rules'][i][kfield]['date'].nil?
                if event.get(kfield).is_a?(String) and not event.get(kfield).nil? and event.get(kfield).length > 0
                  unless @sig_db['rules'][i][kfield]['date']['egal'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)) == (tnow - @sig_db['rules'][i][kfield]['date']['egal'])
                      sig_add[kfield.to_s]="Value date  #{event.get(kfield)} == #{@sig_db['rules'][i][kfield]['date']['egal']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['date']['sup'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)) > (tnow - @sig_db['rules'][i][kfield]['date']['sup'])
                      sig_add[kfield.to_s]="Value date  #{event.get(kfield)} > #{@sig_db['rules'][i][kfield]['date']['sup']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['date']['inf'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)) < (tnow - @sig_db['rules'][i][kfield]['date']['inf'])
                      sig_add[kfield.to_s]="Value date  #{event.get(kfield)} < #{@sig_db['rules'][i][kfield]['date']['inf']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['date']['diff'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)) != (tnow - @sig_db['rules'][i][kfield]['date']['diff'])
                      sig_add[kfield.to_s]="Value date  #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['date']['diff']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                elsif event.get(kfield).is_a?(Array) and not event.get(kfield).nil? and event.get(kfield).length > 0
                  for elem_list in event.get(kfield)
                    if elem_list.is_a?(String)
                      unless @sig_db['rules'][i][kfield]['date']['egal'].nil?
                        check_sig=false
                        if Time.parse(elem_list) == (tnow - @sig_db['rules'][i][kfield]['date']['egal'])
                          sig_add[kfield.to_s]="Value date  #{event.get(kfield)} == #{@sig_db['rules'][i][kfield]['date']['egal']} found"
                          check_sig=true
                        end
                      end
                      break if check_sig == false
                      unless @sig_db['rules'][i][kfield]['date']['sup'].nil?
                        check_sig=false
                        if Time.parse(elem_list) > (tnow - @sig_db['rules'][i][kfield]['date']['sup'])
                          sig_add[kfield.to_s]="Value date  #{event.get(kfield)} > #{@sig_db['rules'][i][kfield]['date']['sup']} found"
                          check_sig=true
                        end
                      end
                      break if check_sig == false
                      unless @sig_db['rules'][i][kfield]['date']['inf'].nil?
                        check_sig=false
                        if Time.parse(elem_list) < (tnow - @sig_db['rules'][i][kfield]['date']['inf'])
                          sig_add[kfield.to_s]="Value date  #{event.get(kfield)} < #{@sig_db['rules'][i][kfield]['date']['inf']} found"
                          check_sig=true
                        end
                      end
                      break if check_sig == false
                      unless @sig_db['rules'][i][kfield]['date']['diff'].nil?
                        check_sig=false
                        if Time.parse(elem_list) != (tnow - @sig_db['rules'][i][kfield]['date']['diff'])
                          sig_add[kfield.to_s]="Value date  #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['date']['diff']} found"
                          check_sig=true
                        end
                      end
                      break if check_sig == false
                    end
                  end
                end
              end
              #END : CHECK BY date
              #BEGIN : CHECK BY hour
              unless @sig_db['rules'][i][kfield]['hour'].nil?
                if event.get(kfield).is_a?(String) and not event.get(kfield).nil?
                  unless @sig_db['rules'][i][kfield]['hour']['egal'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).hour.to_i == @sig_db['rules'][i][kfield]['hour']['egal'].to_i
                      sig_add[kfield.to_s]="Value hour  #{event.get(kfield)} == #{@sig_db['rules'][i][kfield]['hour']['egal'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['hour']['sup'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).hour.to_i > @sig_db['rules'][i][kfield]['hour']['sup'].to_i
                      sig_add[kfield.to_s]="Value hour  #{event.get(kfield)} > #{@sig_db['rules'][i][kfield]['hour']['sup'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['hour']['inf'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).hour.to_i < @sig_db['rules'][i][kfield]['hour']['inf'].to_i
                      sig_add[kfield.to_s]="Value hour  #{event.get(kfield)} < #{@sig_db['rules'][i][kfield]['hour']['inf'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['hour']['diff'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).hour.to_i != @sig_db['rules'][i][kfield]['hour']['diff'].to_i
                      sig_add[kfield.to_s]="Value hour  #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['hour']['diff'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                end
              end
              #END : CHECK BY hour
              #BEGIN : CHECK BY day
              unless @sig_db['rules'][i][kfield]['day'].nil?
                if event.get(kfield).is_a?(String) and not event.get(kfield).nil?
                  unless @sig_db['rules'][i][kfield]['day']['egal'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).wday.to_i == @sig_db['rules'][i][kfield]['day']['egal'].to_i
                      sig_add[kfield.to_s]="Value day  #{event.get(kfield)} == #{@sig_db['rules'][i][kfield]['day']['egal'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['day']['sup'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).wday.to_i > @sig_db['rules'][i][kfield]['day']['sup'].to_i
                      sig_add[kfield.to_s]="Value day  #{event.get(kfield)} > #{@sig_db['rules'][i][kfield]['day']['sup'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['day']['inf'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).wday.to_i < @sig_db['rules'][i][kfield]['dat']['inf'].to_i
                      sig_add[kfield.to_s]="Value day  #{event.get(kfield)} < #{@sig_db['rules'][i][kfield]['day']['inf'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['day']['diff'].nil?
                    check_sig=false
                    if Time.parse(event.get(kfield)).wday.to_i != @sig_db['rules'][i][kfield]['day']['diff'].to_i
                      sig_add[kfield.to_s]="Value day  #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['day']['diff'].to_s} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                end
              end
              #END : CHECK BY day
              #BEGIN : CHECK BY ip adress
              unless @sig_db['rules'][i][kfield]['ipaddr'].nil?
                if event.get(kfield).is_a?(String) and not event.get(kfield).nil?
                  unless @sig_db['rules'][i][kfield]['ipaddr']['egal'].nil?
                    check_sig=false
                    net = IPAddr.new(@sig_db['rules'][i][kfield]['ipaddr']['egal'])
                    if net===event.get(kfield).to_s
                      sig_add[kfield.to_s]="Value IP address #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['ipaddr']['egal']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['ipaddr']['diff'].nil?
                    check_sig=false
                    net = IPAddr.new(@sig_db['rules'][i][kfield]['ipaddr']['diff'])
                    if not net===event.get(kfield).to_s
                      sig_add[kfield.to_s]="Value IP address #{event.get(kfield)} != #{@sig_db['rules'][i][kfield]['ipaddr']['diff']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                end
              end
              #END : CHECK BY ip adress
              #BEGIN : CHECK BY size field operation
              unless @sig_db['rules'][i][kfield]['sizeope'].nil?
                if event.get(kfield).is_a?(String) and not event.get(kfield).nil?
                  unless @sig_db['rules'][i][kfield]['sizeope']['egal'].nil?
                    check_sig=false
                    if event.get(kfield).length == @sig_db['rules'][i][kfield]['sizeope']['egal']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield).length} == #{@sig_db['rules'][i][kfield]['sizeope']['egal']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['sizeope']['sup'].nil?
                    check_sig=false
                    if event.get(kfield).length > @sig_db['rules'][i][kfield]['sizeope']['sup']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield).length} > #{@sig_db['rules'][i][kfield]['sizeope']['sup']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['sizeope']['inf'].nil?
                    check_sig=false
                    if event.get(kfield).length < @sig_db['rules'][i][kfield]['sizeope']['inf']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield).length} < #{@sig_db['rules'][i][kfield]['sizeope']['inf']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                  unless @sig_db['rules'][i][kfield]['sizeope']['diff'].nil?
                    check_sig=false
                    if event.get(kfield).length != @sig_db['rules'][i][kfield]['sizeope']['diff']
                      sig_add[kfield.to_s]="Value numeric  #{event.get(kfield).length} != #{@sig_db['rules'][i][kfield]['sizeope']['diff']} found"
                      check_sig=true
                    end
                  end
                  break if check_sig == false
                end
              end
              #END : CHECK BY size field operation
              #BEGIN : CHECK BY regexp
              unless @sig_db['rules'][i][kfield]['regexp'].nil?
                check_sig=false
                for regexp in @sig_db['rules'][i][kfield]['regexp']
                  if event.get(kfield).is_a?(String) and not event.get(kfield).nil?
                    match = Regexp.new(regexp, nil, 'n').match(event.get(kfield))
                    if not match.nil?
                      sig_add[kfield.to_s]="Regexp found #{match}"
                      check_sig=true
                      break
                    end
                  elsif event.get(kfield).is_a?(Array)
                    for elem_list in event.get(kfield)
                      if elem_list.is_a?(String)
                        match = Regexp.new(regexp, nil, 'n').match(elem_list)
                        if not match.nil?
                          sig_add[kfield.to_s]="Regexp found #{match}"
                          check_sig=true
                          break
                        end
                      end
                    end
                  end
                end
              end
              break if check_sig == false
              #END : CHECK BY regexp
              #BEGIN : CHECK BY regexp excluse (not present)
              unless @sig_db['rules'][i][kfield]['notregexp'].nil?
                check_sig=false
                regexplen=@sig_db['rules'][i][kfield]['notregexp'].length
                veriflen=0
                for regexp in @sig_db['rules'][i][kfield]['notregexp']
                  if event.get(kfield).is_a?(String)
                    match = Regexp.new(regexp, nil, 'n').match(event.get(kfield))
                    if match.nil?
                      veriflen=veriflen+1
                    end
                  elsif event.get(kfield).is_a?(Array)
                    for elem_list in event.get(kfield)
                      if elem_list.is_a?(String)
                        match = Regexp.new(regexp, nil, 'n').match(elem_list)
                        if match.nil?
                          veriflen=veriflen+1
                        end
                      end
                    end  
                  end
                end
                if veriflen==regexplen
                  sig_add[kfield.to_s]="Not Regexp present: OK"
                  check_sig=true
                end
              end
              break if check_sig == false
              #END : CHECK BY regexp excluse (not present)
              #CHECK SIG BY FIELD END
              #check SIG RESULT FIND and get information name, type, modefp, note, id
              if check_sig == true
                validfield = validfield + 1
                if @sig_db['rules'][i][kfield]['id'].is_a?(Numeric)
                  sig_add["id"] = @sig_db['rules'][i][kfield]['id'].to_i
                else
                  #all information must to be on same field
                  next
                end
                if @sig_db['rules'][i][kfield]['name'].is_a?(String)
                  if sig_add["name_sig"].nil?
                    sig_add["name_sig"] = @sig_db['rules'][i][kfield]['name']
                  else
                    sig_add["name_sig"] = sig_add["name_sig"] + @sig_db['rules'][i][kfield]['name']
                  end
                end
                if @sig_db['rules'][i][kfield]['type'].is_a?(Numeric)
                  if @sig_db['rules'][i][kfield]['type'] == 2
                    type_sig = type_sig + 1
                  end
                  if @sig_db['rules'][i][kfield]['type'] == 1
                    type_obl = type_obl + 1
                  end
                end
                if @sig_db['rules'][i][kfield]['modeFP'].nil?
                  if @sig_db['rules'][i][kfield]['modeFP'] == true
                    sig_add["modeFP"] = true
                  end
                end
                if @sig_db['rules'][i][kfield]['note'].is_a?(Numeric)
                  if sig_add["note"].nil?
                    sig_add["note"] = @sig_db['rules'][i][kfield]['note'].to_s
                  else
                    sig_add["note"] = (sig_add["note"].to_i + @sig_db['rules'][i][kfield]['note'].to_i).to_s
                  end
                end
                if @sig_db['rules'][i][kfield]['extract'].is_a?(Hash)
                  sig_add["extract"] = @sig_db['rules'][i][kfield]['extract']
                end
                #"freq_field:" [field,field,field,field],"freq_delay":60s,freq_count: 3, freq_resettime: 3600s, correlate_change_fieldvalue: []
                #use for correlate multi event type with correlate_change_fieldvalue
                # or use for freq select, by exemple brute force without correlate_change_fieldvalue
                if @sig_db['rules'][i][kfield]['freq_field'].is_a?(Array) and @sig_db['rules'][i][kfield]['freq_delay'].is_a?(Interger) and @sig_db['rules'][i][kfield]['freq_resettime'].is_a?(Integer) and @sig_db['rules'][i][kfield]['freq_count'].is_a?(Integer)
                  sig_add["freq_field"] = @sig_db['rules'][i][kfield]['freq_field']
                  sig_add["freq_delay"] = @sig_db['rules'][i][kfield]['freq_delay']
                  sig_add["freq_count"] = @sig_db['rules'][i][kfield]['freq_count']
                  sig_add["freq_resettime"] = @sig_db['rules'][i][kfield]['freq_resettime']
                  if @sig_db['rules'][i][kfield]['correlate_change_fieldvalue'].is_a?(Array) and not @sig_db['rules'][i][kfield]['correlate_change_fieldvalue'].empty?
                    sig_add["correlate_change_fieldvalue"] = @sig_db['rules'][i][kfield]['correlate_change_fieldvalue']
                  end
                end 
              end
              #end check result find
            end
            #verify all field checked and all checks are matched
            if countfield > 0 and countfield == validfield
              #if mode FP break and delete event
              if sig_add["modeFP"] == true
                #@logger.warn("DROP EVENT FP:", :string => sig_add["name_sig"])
                sig_add.clear
                detected_sig.clear
                detected_sig_count=0
                event.cancel
                return
              end
              #detected freq & correlate
              if sig_add["freq_field"]
                #get id sig for know if you create alert or no
                #example if just id match then don't create alert
                detected_sig_id_corre.push(*sig_add["id"])
                #create hash of event
                fields_value=""
                for fx in sig_add["freq_field"]
                  if event.get(fx)
                    fields_value = fields_value + event.get(fx).to_s.downcase
                  end
                end
                hash_field = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, "SIG-PLUGIN-FREQ", fields_value.to_s).force_encoding(Encoding::UTF_8)
                if @sig_db_freq[hash_field]     
                  #hash in db
                  #verify if valid is false
                  if @sig_db_freq[hash_field]['valid'] == false
                    #ok hash not matched
                    #verify delay
                    if @sig_db_freq[hash_field]['delay'] < tnow
                      #delay is out
                      #restart of 0
                      @sig_db_freq[hash_field]['count'] = 1
                      @sig_db_freq[hash_field]['delay'] = tnow + sig_add["freq_delay"]
                      if sig_add["correlate_change_fieldvalue"]
                        fields-corre_value=""
                        @sig_db_freq[hash_field]['corre_value'] = []
                        for fy in sig_add["freq_field"]
                          if event.get(fy)
                            fields-corre_value = fields-corre_value + event.get(fy).to_s.downcase
                          end
                        end
                        @sig_db_freq[hash_field]['corre_value'].push(*OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, "SIG-PLUGIN-FREQ", fields-corre_value.to_s).force_encoding(Encoding::UTF_8))
                      end 
                      @sig_db_freq[hash_field]['valid'] = false
                    else
                      #ok count, because delay is valid
                      #check if sig_add["correlate_change_fieldvalue"] is present
                      hash-corre_value = ""
                      if sig_add["correlate_change_fieldvalue"]
                        fields-corre_value=""
                        for fy in sig_add["freq_field"]
                          if event.get(fy)
                            fields-corre_value = fields-corre_value + event.get(fy).to_s.downcase
                          end
                        end
                        hash-corre_value = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, "SIG-PLUGIN-FREQ", fields-corre_value.to_s).force_encoding(Encoding::UTF_8)
                        if not @sig_db_freq[hash_field]['corre_value'].include?(hash-corre_value)
                          #if correlate hash not exist count ++
                          @sig_db_freq[hash_field]['count'] = @sig_db_freq[hash_field]['count'] + 1
                          @sig_db_freq[hash_field]['corre_value'].push(*hash-corre_value)
                        end
                      else
                        #no correlate
                        @sig_db_freq[hash_field]['count'] = @sig_db_freq[hash_field]['count'] + 1
                      end
                      #verify if count reach count_value rule
                      if @sig_db_freq[hash_field]['count'] >= sig_add["freq_resettime"]
                        #valid sig
                        @sig_db_freq[hash_field]['delay'] = tnow + sig_add["freq_resettime"]
                        @sig_db_freq[hash_field]['valid'] = true
                        detected_sig_id_corre.clear
                      end
                    end
                  else
                    #hash matched in past, verify if resettime is passed?
                    if @sig_db_freq[hash_field]['delay'] < tnow
                      #delay is passed, restart to 0
                      @sig_db_freq[hash_field]['count'] = 1
                      if sig_add["correlate_change_fieldvalue"]
                        @sig_db_freq[hash_field]['corre_value'] = []
                        fields-corre_value=""
                        for fy in sig_add["freq_field"]
                          if event.get(fy)
                            fields-corre_value = fields-corre_value + event.get(fy).to_s.downcase
                          end
                        end
                        @sig_db_freq[hash_field]['corre_value'].push(*OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, "SIG-PLUGIN-FREQ", fields-corre_value.to_s).force_encoding(Encoding::UTF_8))
                      end
                      @sig_db_freq[hash_field]['delay'] = tnow + sig_add["freq_delay"]
                      @sig_db_freq[hash_field]['valid'] = false
                    end
                  end
                else
                  #new hash
                  @sig_db_freq[hash_field] = {}
                  @sig_db_freq[hash_field]['count'] = 1
                  if sig_add["correlate_change_fieldvalue"]
                    fields-corre_value=""
                    @sig_db_freq[hash_field]['corre_value'] = []
                    for fy in sig_add["freq_field"]
                      if event.get(fy)
                        fields-corre_value = fields-corre_value + event.get(fy).to_s.downcase
                      end
                    end
                    @sig_db_freq[hash_field]['corre_value'].push(*OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, "SIG-PLUGIN-FREQ", fields-corre_value.to_s).force_encoding(Encoding::UTF_8))
                  end
                  @sig_db_freq[hash_field]['delay'] = tnow + sig_add["freq_delay"]
                  @sig_db_freq[hash_field]['valid'] = false
                end
              end
              #detected_extract
              if sig_add["extract"]
                #extract field and insert in ioc local
                sig_add["extract"].each do |ekey,eval|
                  if event.get(ekey) and @ioc_db_local
                    if @ioc_db_local[eval]
                      unless @ioc_db_local[eval].include?(event.get(ekey))
                        @ioc_db_local[eval].push(*event.get(ekey))
                        sleep(1) until @load_statut_ioc
                        @load_statut_ioc = false
                        @ioc_db = @ioc_db.merge(db_tmp) {|key, first, second| first.is_a?(Array) && second.is_a?(Array) ? first | second : second }
                        @load_statut_ioc = true
                      end
                    else
                      @ioc_db_local[eval] = []
                      @ioc_db_local[eval].push(*event.get(ekey))
                      sleep(1) until @load_statut_ioc
                      @load_statut_ioc = false
                      @ioc_db = @ioc_db.merge(db_tmp) {|key, first, second| first.is_a?(Array) && second.is_a?(Array) ? first | second : second }
                      @load_statut_ioc = true
                    end
                  end
                end
              end
              detected_sig.push(*sig_add)
              #no continu if one rule match
              if @check_stop 
                detected_sig_count = 1
                detected_sig_note = sig_add["note"].to_i
                detected_sig_id.push(*sig_add["id"])
                detected_sig_name.push(*sig_add["name_sig"])
                sig_add.clear
                break
              else
                detected_sig_count = detected_sig_count + 1
                detected_sig_name.push(*sig_add["name_sig"])
                detected_sig_id.push(*sig_add["id"])
                if detected_sig_note < sig_add["note"].to_i
                  detected_sig_note = sig_add["note"].to_i
                end
                sig_add.clear
              end
            else
              sig_add.clear
            end
          end
        end
      end
      eventK.clear
      #check if sig detected,  and add to @targetxxx_sig
      if detected_sig.any? and type_sig < detected_sig_count and type_obl > 0
        #verify if not juste correlate rule match
        if detected_sig_id != detected_sig_id_corre
          unless event.get(@target_sig).nil?
            event.set(@target_sig, event.get(@target_sig) + detected_sig) 
          else
            event.set(@target_sig, detected_sig)
          end
          unless event.get(@targetnum_sig).nil?
            event.set(@targetnum_sig, event.get(@targetnum_sig) + detected_sig_count)
          else
            event.set(@targetnum_sig, detected_sig_count)
          end
          unless event.get(@targetnote).nil?
            if event.get(@targetnote) < detected_sig_note
              event.set(@targetnote, detected_sig_note)
            end
          else
            event.set(@targetnote, detected_sig_note)
          end
          unless event.get(@targetname_sig).nil?
            event.set(@targetname_sig, event.get(@targetname_sig) + detected_sig_name)
          else
            event.set(@targetname_sig, detected_sig_name)
          end
          unless event.get(@targetid).nil?
            event.set(@targetid, event.get(@targetid) + detected_sig_id)
          else
            event.set(@targetid, detected_sig_id)
          end
        end
        #@logger.warn("Dectected SIG", :detected_sig_name => detected_sig_name)
      end
    end
    ######################

    ######REFERENCE#######
    #check refresh db ref
    unless @disable_ref
      if @next_refresh_confrules < tnow
        if @load_statut_rules == true
          @load_statut_rules = false
          load_db_ref
          @next_refresh_confrules = tnow + @refresh_interval_confrules
          @load_statut_rules = true
        end
      end
      sleep(1) until @load_statut_rules
    end
    #check if db and rule not empty 
    if not @ref_rules.empty? and not @ref_db.empty? and not @pattern_db and not @disable_ref and event.get(@noapply_ref).nil?
      #list all rules
      #!!!! amelioration de la sig avec simhash...
      detected_ref = Array.new
      detected_ref_field = Array.new
      detected_ref_id = Array.new
      detected_ref_err_count = 0
      detected_ref_note = 0
      eventK = event.to_hash.keys
      for r_rule in @ref_rules
        #rules[ {"pivot_field":{field1:'value'},{field2:'value'}, "list_sig": [fieldx,fieldy,...], "relation_min": 10, "simhash_size": 16, "simhash_use_size": 14, "id": 200X} ]
        # if pivot containt array, !!! order is important
        # list_sig containt field possible, if one field not exist, it works too
        num_p = r_rule["pivot_field"].keys.length
        pivot = r_rule["pivot_field"].keys & eventK
        tmp_detect={}
        tmp_detect[r_rule["id"].to_s]={}
        #heck if pivot present in event
        if num_p == pivot.length
            stop = false
            for keyx in pivot
              if event.get(keyx) === r_rule["pivot_field"][keyx]
                stop = true
                break
              end
            end
            next if stop
            if @ref_db[r_rule["id"].to_s]
            #{ 'ID20XXXX': {
            #                                                                      'field': {
            #                                                                                 'TYPE': 'Array|Int|String|...',
            #                                                                                 'Uniq_value': true or false, #define if value is random => true
            #                                                                                 'NOTE_UNIQ_REDUC': 0.1 # for reduce note if match on uniq fueld            
            #                                                                                 'LIST_VALUE': ['value_possible1','value_possible2','value_possibleX'],
            #                                                                                 'NOTE_LISTV': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'ENCODING': true or false, # value contains than ascii caratere
            #                                                                                 'NOTE_ENCODING': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'LEN_MAX': numeric_value,
            #                                                                                 'NOTE_LEN': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'LEN_MIN': numeric_value,
            #                                                                                 'LEN_AVG': numeric_value,
            #                                                                                 'LEN_AVG_PRCT': pourcent for AVG,
            #                                                                                 'NOTE_LEN_AVG': 0.1 # note between 0.x and 4 default 0.1
            #                                                                                 'LEN_EVENorUNEVENnum': numeric_value, #even num = 1;uneven num = 2; unknown/undefine = 0
            #                                                                                 'NOTE_LEN_EVEN': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'REGEXP_MIN': [],
            #                                                                                 'NOTE_REGEXP_MIN': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'REGEXP': []
            #                                                                                 'NOTE_REGEXP': 0.25 # note between 0.x and 4 default 0.25
            #                                                                               } ,
            #                                                                      #relation value_fix contains list of value of field not unique (random)
            #                                                                      # by exemple fld1: '1'; fld2: 'blabla';fld3: '10.10.10.10'
            #                                                                      # create LIST simhash value and attention to order field
            #                                                                      # you can optimiz with simhash - end if earn place memory
            #                                                                      # important you count SIMHASH:COUNT for use COUNT if very little score => suspect [use conf -> relation_min]
            #                                                                      'relation_value_fix": {'SIMHASH1':COUNTX,'SIMHASH2':COUNTY,'SIMHASH3':COUNTX},
            #                                                                      'NOTE_DEFAULT': 2# note between 0.x and 4 default 2
            # !!!!!!!!!!!!!!! if NOTE or relation_value_fix is name of real field == problem!!!!
            #                                                                      }}}
            #create sig event
            sig_tmp = r_rule["list_sig"] & eventK
            if sig_tmp.any?
              #sif is not empty
              #CHECK FIELD by FIELD
              sig_not_uniq = []
              for field in sig_tmp
                tmp_detect[r_rule["id"].to_s][field.to_s]={}
                string_field = true
                #CHECK: TYPE -> int/string/array/hash/... not for note, juste for next step for good choice => nummber or string analysis
                if ['boolean', 'long', 'integer', 'short', 'byte', 'double', 'float'].include?(@ref_db[r_rule["id"].to_s][field]['TYPE'].to_s )
                  string_field = false
                end
                #CHECK: LIST_VALUE is not empty then check if contains
                if not @ref_db[r_rule["id"].to_s][field]['LIST_VALUE'].empty? and not @ref_db[r_rule["id"].to_s][field]['LIST_VALUE'].include?(event.get(field.to_s))
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_LISTV']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['LIST_VALUE']="Value not in list: " + event.get(field.to_s)
                end
                #CHECK: ENCODING char, not check if not string
                if string_field and not @ref_db[r_rule["id"].to_s][field]['ENCODING'].include?(event.get(field.to_s).encoding.to_s)
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_ENCODING']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['ENCODING']=event.get(field.to_s).encoding.to_s
                end
                #CHECK: TYPE class of number, not check for string
                if not string_field and not @ref_db[r_rule["id"].to_s][field]['ENCODING'].include?(event.get(field.to_s).class.to_s)
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_ENCODING']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['ENCODING']=event.get(field.to_s).encoding.to_s
                end
                #CHECK: LEN for compare to MAX/MIN/AVG
                f_len=0
                #DIfferent check if field type string or number
                if string_field
                  f_len=event.get(field.to_s).length
                else
                  f_len=event.get(field.to_s)
                end
                prct_h = @ref_db[r_rule["id"].to_s][field]['LEN_AVG'].to_f + ( @ref_db[r_rule["id"].to_s][field]['LEN_AVG'].to_f / 100.to_f * @ref_db[r_rule["id"].to_s][field]['LEN_AVG_PRCT'].to_f )
                prct_l = @ref_db[r_rule["id"].to_s][field]['LEN_AVG'].to_f - ( @ref_db[r_rule["id"].to_s][field]['LEN_AVG'].to_f / 100.to_f * @ref_db[r_rule["id"].to_s][field]['LEN_AVG_PRCT'].to_f )
                if f_len > @ref_db[r_rule["id"].to_s][field]['LEN_MAX'] or f_len < @ref_db[r_rule["id"].to_s][field]['LEN_MIN'] or (prct_l >= f_len.to_f and f_len.to_f <= prct_h)
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_LEN']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['LEN']=f_len
                end
                #CHECK: type number (unven/uneven) if value different of 0
                f_len_even = 2
                if f_len.even?
                 f_len_even = 1
                end
                if @ref_db[r_rule["id"].to_s][field]['LEN_EVENorUNEVENnum'] != 0 and f_len_even != @ref_db[r_rule["id"].to_s][field]['LEN_EVENorUNEVENnum']
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_LEN_EVEN']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['LEN_EVEN']=f_len_even
                end
                #CHECK: Regexp pattern Normaly/MInimal
                #create regexp list match of field
                rlist = []
                @pattern_db.each do |key, value|
                  match = Regexp.new(value, nil, 'n').match(event.get(field.to_s).to_s)
                  if not match.nil?
                    rlist << key
                  end
                end
                #intersection with reference
                regexp_min = @ref_db[r_rule["id"].to_s][field]['REGEXP_MIN'] & rlist
                #if all reference not present in event
                if regexp_min.length != @ref_db[r_rule["id"].to_s][field]['REGEXP_MIN'].length
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_REGEXP_MIN']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['REGEXP_MIN']=regexp_min - rlist
                end
                #create regexp sig
                srlist=rlist.join("::")
                #Search regexp sig in reference
                unless @ref_db[r_rule["id"].to_s][field]['REGEXP'].include?(srlist)
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE_REGEXP']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['REGEXP']=srlist
                end
                #CHECK: Unique Value -> create SIG UNIQ
                unless @ref_db[r_rule["id"].to_s][field]['Uniq_value']
                  sig_not_uniq << field.to_s
                end
              end
              #CHECK: GLOBAL relation of uniq field by simhash for PIVOT->SIG
              #create simhash of sig_not_uniq value
              sig_not_uniq = sig_not_uniq.sort
              sig_not_uniq_value = []
              for xfield in sig_not_uniq
                sig_not_uniq_value << event.get(xfield.to_s)
              end
              #create simhash
              sig_not_uniq_value = sig_not_uniq_value.to_s.force_encoding('iso-8859-1').encode('utf-8') #string
              simhash_event = sig_not_uniq_value.simhash(:hashbits => r_rule["simhash_size"]).to_s
              if @ref_db[r_rule["id"].to_s]['relation_value_fix'].key?(simhash_event)
                #present , verify count
                if @ref_db[r_rule["id"].to_s]['relation_value_fix'][simhash_event] < r_rule["relation_min"]
                  # more less than count_min
                  detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE']
                  detected_ref_err_count = detected_ref_err_count + 1
                  detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                  detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                  tmp_detect[r_rule["id"].to_s][field.to_s]['RELATION_LOW']=simhash_event
                end
              else
                # not present
                detected_ref_note = detected_ref_note + @ref_db[r_rule["id"].to_s][field]['NOTE']
                detected_ref_err_count = detected_ref_err_count + 1
                detected_ref_id.push(*r_rule["id"]) if not detected_ref_id.include?(r_rule["id"])
                detected_ref_field.push(*field.to_s) if not detected_ref_field.include?(field.to_s)
                tmp_detect[r_rule["id"].to_s][field.to_s]['RELATION']=simhash_event
              end
              detected_ref.push(*tmp_detect)
            end
          end
        end
        if @ref_stop_after_firstffind and detected_ref_err_count > 0
          break
        end
      end
      #add detected to event
      if detected_ref.any? and detected_ref_err_count > 0
        unless event.get(@target_ref).nil?
          event.set(@target_ref, event.get(@target_ref) + detected_ref)
        else
          event.set(@target_ref, detected_ref)
        end
        unless event.get(@targetnum_ref).nil?
          event.set(@targetnum_ref, event.get(@targetnum_ref) + detected_ref_err_count)
        else
          event.set(@targetnum_ref, detected_ref_err_count)
        end
        detected_ref_note = ( detected_ref_note + @ref_aroundfloat ).to_i #around float to int -- default + 0.5
        if detected_ref_note > 4
          detected_ref_note = 4
        end
        unless event.get(@targetnote).nil?
          if event.get(@targetnote) < detected_ref_note
            event.set(@targetnote, detected_ref_note)
          end
        else
          event.set(@targetnote, detected_ref_note)
        end
        unless event.get(@targetname_ref).nil?
          event.set(@targetname_ref, event.get(@targetname_ref) + detected_ref_field)
        else
          event.set(@targetname_ref, detected_ref_field)
        end
        unless event.get(@targetid).nil?
          event.set(@targetid, event.get(@targetid) + detected_ref_id)
        else
          event.set(@targetid, detected_ref_id)
        end
        #@logger.warn("Dectected SIG", :detected_sig_name => detected_sig_name)
      end
    end
    ######################
    
    ######## NOTE ########
    #check refresh db note
    if not event.get(@targetid).nil? and not @disable_note
      if @next_refresh_note < tnow
        if @load_statut_note == true
          @load_statut_note = false
          load_conf_rules_note
          @next_refresh_note = tnow + @refresh_interval_confrules
          @load_statut_note = true
        end
      end
      sleep(1) until @load_statut_note
    end
    #check if db note empty and @targetid in event exist
    if not @note_db.empty? and not event.get(@targetid).nil? and not @disable_note
      note_max=0
      overwrite=false
      #check all rules
      for r_note in @note_db
        #check note
        if r_note['id'] #id must present
          if r_note['id'].is_a?(Array) #id must be type Array
            verif=r_note['id'].length
            #create intersection with event id and id present in rule
            intersec = event.get(@targetid) & r_note['id'] 
            #verify all id present in event
            if not intersec.length == verif
              next
            end
          end
          #check if option id present in rule
          if not r_note['optid'].nil? and not r_note['opt_num'].nil? #id find with opt_num present
            intersec = event.get(@targetid) & r_note['optid'] #create intersection
            #verify minimum X (@opt_num) present in event
            if not intersec.length >= r_note['opt_num'].to_i
              next
            end
          end
          #check if not id present option in rule
          if r_note['noid'].is_a?(Array) and not r_note['noid'].empty?
            intersec = event.get(@targetid) & r_note['noid'] #create intersection
            #verify none id present in event
            if not intersec.length == 0
              next
            end
          end
          #change note if upper
          if note_max < r_note['note']
            note_max = r_note['note']
            # if option overwrite, change note even if note lower
            if r_note['overwrite']
              overwrite=true
            end
          end
        end
      end
      if note_max != 0 
        if ( event.get(@targetnote) > note_max and overwrite ) or ( event.get(@targetnote) < note_max )
          event.set(@targetnote, note_max)
        end
      end
    end
    ######################
    
    ######FINGERPRINT USE & DROP END######
    # create fingerprint at end because, you need to have sig & ioc detected for unique event
    #refresh db & conf fingerprint
    unless @disable_fp
      if @next_refresh_conffp < tnow
        if @load_statut_fp == true
          @load_statut_fp = false
          load_conf_fp
          load_db_dropfp
          @next_refresh_conffp = tnow + @refresh_interval_conffp
          @load_statut_fp = true
        end
      end
      sleep(1) until @load_statut_fp
    end
    #chekc if db &conf are not empty + select_fp exist
    if not @fp_rules.empty? and not @fp_db.empty? and not event.get(@select_fp).nil? and not @disable_fp
      to_string = ""
      #select_fp can be type Array or String
      if event.get(@select_fp).is_a?(Array)
        for elemsfp in event.get(@select_fp)
          #check if rules match with select_fp (case: Array)
          if @fp_rules.key?(elemsfp.to_s)
            if @fp_rules[elemsfp.to_s]['fields'].is_a?(Array) and @fp_rules[elemsfp.to_s]['hashbit'].is_a?(Numeric)
              #create fingerprint
              @fp_rules[elemsfp.to_s]['fields'].sort.each do |k|
                if event.get(k)
                  to_string << "|#{k}|#{event.get(k)}"
                end
              end
              to_string << "|"
              to_string = to_string.force_encoding('iso-8859-1').encode('utf-8') #string
              event.set(@target_fp, to_string.simhash(:hashbits => @fp_rules[elemsfp.to_s]['hashbit']).to_s)
              #check db fp drop
              if event.get(@noapply_sig_dropfp).nil? and @fp_db[event.get(@target_fp)]
                event.cancel
                return
              end
              if @fingerprint_db[event.get(@target_fp)]
                #key existe -- event known
                if @fingerprint_db[event.get(@target_fp)] < tnow
                  #date is passed
                  @fingerprint_db[event.get(@target_fp)] = tnow +@fp_rules[elemsfp.to_s]['delay']
                  #(event[@target_tag_fp] ||= []) << @tag_name_first
                  event.set(@target_tag_fp, []) unless event.get(@target_tag_fp)
                  event.set(@target_tag_fp, event.get(@target_tag_fp) + @tag_name_first)
                else
                  #add tag
                  #(event.get(@target_tag_fp) ||= []) << @tag_name_after
                  event.set(@target_tag_fp, []) unless event.get(@target_tag_fp)
                  event.set(@target_tag_fp, event.get(@target_tag_fp) + @tag_name_after)
                end
              else
                #key not exist -- new event
                @fingerprint_db[event.get(@target_fp)] = tnow + @fp_rules[elemsfp.to_s]['delay']
                #(event[@target_tag_fp] ||= []) << @tag_name_first
                event.set(@target_tag_fp, []) unless event.get(@target_tag_fp)
                event.set(@target_tag_fp, event.get(@target_tag_fp) + @tag_name_first)
              end
            end
            break
          end
        end
      #check if rules match with select_fp (case String)
      elsif event.get(@select_fp).is_a?(String) and @fp_rules.key?(event.get(@select_fp))
        if @fp_rules[event.get(@select_fp)]['fields'].is_a?(Array) and @fp_rules[event.get(@select_fp)]['hashbit'].is_a?(Integer)
          #create fingerprint
          @fp_rules[event.get(@select_fp)]['fields'].sort.each do |k|
            if event.get(k)
              to_string << "|#{k}|#{event.get(k)}"
            end
          end
          to_string << "|"
          to_string = to_string.force_encoding('iso-8859-1').encode('utf-8') #string
          event.set(@target_fp, to_string.simhash(:hashbits => @fp_rules[event.get(@select_fp)]['hashbit']).to_s)
          #check db fp drop
          if event.get(@noapply_sig_dropfp).nil? and @fp_db[event.get(@target_fp)]
            event.cancel
            return
          end
          if @fingerprint_db[event.get(@target_fp)]
            #key existe -- event known
            if @fingerprint_db[event.get(@target_fp)] < tnow
              #date is passed
              @fingerprint_db[event.get(@target_fp)] = tnow +@fp_rules[event.get(@select_fp)]['delay']
              #(event[@target_tag_fp] ||= []) << @tag_name_first
              event.set(@target_tag_fp, []) unless event.get(@target_tag_fp)
              event.set(@target_tag_fp, event.get(@target_tag_fp) + @tag_name_first)
            else
              #add tag
              #(event[@target_tag_fp] ||= []) << @tag_name_after
              event.set(@target_tag_fp, []) unless event.get(@target_tag_fp)
              event.set(@target_tag_fp, event.get(@target_tag_fp) + @tag_name_after)
            end
          else
            #key not exist -- new event
            @fingerprint_db[event.get(@target_fp)] = tnow + @fp_rules[event.get(@select_fp)]['delay']
            #(event[@target_tag_fp] ||= []) << @tag_name_first
            event.set(@target_tag_fp, []) unless event.get(@target_tag_fp)
            event.set(@target_tag_fp, event.get(@target_tag_fp) + @tag_name_first)
          end
        end
      end
    end
    ###########################
    
    ######## FREQ EVENT ########
    #rules_freq = [ {'select_field': {'fieldx':[value_list],'fieldy':[value_list]}, 'note': X, 'refresh_time': Xseconds,'reset_time': Xseconds[1j], 'reset_hour': '00:00:00', 'wait_after_reset': 10, 'id': 30XXX},...]
    #TODO: CREATE TEMPLATE FOR NEW MESSAGE
    #select field for select => first filter
    #select field value => second filter
    #refresh_time for check and calculate all time result: max & variation
    # note if match
    # reset time in second for reset all counter value
    # reset hour for begin reset with hour => use for 24h reset begin at 00:00
    # wait_after_reset: dont't check before 10 times values
    #db_freq = { '30XXX': {'status_acces':true,'reset_time': date,'refresh_date': date, 'old_date': date,'num_time': Xtimes, 'V_prev': x/m, 'Varia_avg': z/m, 'count_prev': Xtimes, 'count_cour': Xtimes, 'V_max': x/m, 'Varia_max': x/m, 'Varia_min': +/- x/m, 'Varia_glob': x/m}}
    #check refresh db ref
    #
    unless @disable_freq
      if @next_refresh_freqrules < tnow
        if @load_statut_freqrules == true
          @load_statut_freqrules = false
          load_rules_freq # load rules and create db_freq with init var 
          @next_refresh_freqrules = tnow + @refresh_interval_freqrules
          @load_statut_freqrules = true
        end
      end
      sleep(1) until @load_statut_freqrules
    end
    #verify db & rules is not empty
    if not @freq_rules.empty? and not @db_freq.empty? and not @disable_freq and event.get(@noapply_freq).nil?
      eventK = event.to_hash.keys
      #CHECK RULE BY RULE
      no_match = true
      for f_rule in @freq_rules
        f_rule.each do |fkey,fval|
          #VERIFY FIELD by FIELD if present and value match
          no_match = true
          if not event.get(fkey.to_s).nil? and fval.include?(event.get(fkey.to_s))
            no_match = false
          end
          break if no_match
        end
        # if rule no match then next
        next if no_match
        # if rule match increment count
        if @db_freq[f_rule['id']]
          #incrimente count
          @db_freq[f_rule['id']]['count_cour'] = @db_freq[f_rule['id']]['count_cour'] + 1
          #check if time to calculate varia & freq
          #check if first time to check
          if ( @db_freq[f_rule['id']]['num_time'] == 0 and @db_freq[f_rule['id']]['status_acces'] == true ) or ( @db_freq[f_rule['id']]['reset_time'] <= tnow and @db_freq[f_rule['id']]['status_acces'] == true )
            #first time
            @db_freq[f_rule['id']]['status_acces'] = false
            #init old_date & refresh date
            @db_freq[f_rule['id']]['reset_time'] = tnow + f_rule['reset_time']
            @db_freq[f_rule['id']]['old_date'] = tnow
            @db_freq[f_rule['id']]['refresh_date'] = tnow + f_rule['refresh_time']
            @db_freq[f_rule['id']]['count_prev'] = @db_freq[f_rule['id']]['count_cour']
            @db_freq[f_rule['id']]['status_acces']['v_max']=0
            @db_freq[f_rule['id']]['status_acces']['varia_min']=10000
            @db_freq[f_rule['id']]['status_acces']['varia_max']=0
            @db_freq[f_rule['id']]['v_prev'] = 1
            @db_freq[f_rule['id']]['varia_glob'] = 0
            @db_freq[f_rule['id']]['num_time'] = 1
            @db_freq[f_rule['id']]['status_acces'] = true
          elsif @db_freq[f_rule['id']]['num_time'] != 0  
            if @db_freq[f_rule['id']]['refresh_date'] <= tnow and @db_freq[f_rule['id']]['status_acces'] == true
              @db_freq[f_rule['id']]['status_acces'] = false
              #time to re-calculate
              # put all in same unit => 60s
              #calculate diff between ald date and new date
              diff_time = tnow - @db_freq[f_rule['id']]['old_date'] #in seconds
              #reinit old_date & refresh date
              @db_freq[f_rule['id']]['old_date'] = tnow
              @db_freq[f_rule['id']]['refresh_date'] = tnow + f_rule['refresh_time']
              #calculate diff between previous count and count courant
              count_diff = @db_freq[f_rule['id']]['count_cour'] - @db_freq[f_rule['id']]['count_prev']
              #reinit count_previous
              @db_freq[f_rule['id']]['count_prev'] = @db_freq[f_rule['id']]['count_cour']
              #calculate v
              v_cour = (((count_diff / diff_time)*60)+0.5).to_i # vcour/60s to interger
              #check v_max
              if @db_freq[f_rule['id']]['v_max'] < v_cour
                @db_freq[f_rule['id']]['v_max'] = v_cour
                #CREATE ALERT
              end
              #cacl varia
              varia_cour = v_cour - db_freq[f_rule['id']]['v_prev']
              #reinit v_prev
              db_freq[f_rule['id']]['v_prev'] = v_cour
              #incriment varia_glob
              db_freq[f_rule['id']]['varia_glob'] = db_freq[f_rule['id']]['varia_glob'] + varia_cour.abs
              #check varia_max & varia_min
              if @db_freq[f_rule['id']]['varia_max'] < varia_cour
                #CREATE ALERT
                if f_rule['wait_after_reset'] < @db_freq[f_rule['id']]['num_time']
                  new_event = LogStash::Event.new
                  new_event.set("message", "ALERT FREQ -- rule id:" + f_rule['id'].to_s + " -- count " + v_cour.to_s + "events for 60s -- VARIA : " + varia_cour.to_s + "(varia courant) -- The value change old varia max: " + @db_freq[f_rule['id']]['varia_max'])
                  new_event.set("type", "alert_freq")
                  new_event.set("ruleid", f_rule['id'].to_s)
                  new_event.set("time", tnow.to_s)
                end
                @db_freq[f_rule['id']]['varia_max'] = varia_cour
              end
              if @db_freq[f_rule['id']]['varia_min'] > varia_cour
                #CREATE ALERT
                if f_rule['wait_after_reset'] < @db_freq[f_rule['id']]['num_time']
                  new_event = LogStash::Event.new
                  new_event.set("message", "ALERT FREQ -- rule id:" + f_rule['id'].to_s + " -- count " + v_cour.to_s + "events for 60s -- VARIA : " + varia_cour.to_s + "(varia courant) -- The value change old varia min: " + @db_freq[f_rule['id']]['varia_min'])
                  new_event.set("type", "alert_freq")
                  new_event.set("ruleid", f_rule['id'].to_s)
                  new_event.set("time", tnow.to_s)
                end
                db_freq[f_rule['id']]['varia_min'] = varia_cour
              end
              #calculate varia_avg
              @db_freq[f_rule['id']]['varia_avg'] = db_freq[f_rule['id']]['varia_glob'] / @db_freq[f_rule['id']]['num_time']
              #incremente num time of calculate
              @db_freq[f_rule['id']]['num_time'] = @db_freq[f_rule['id']]['num_time'] + 1
              #check if varia is more than v_cour
              if varia_cour > @db_freq[f_rule['id']]['varia_avg']
                #CREATE ALERT
                if f_rule['wait_after_reset'] < @db_freq[f_rule['id']]['num_time']
                  new_event = LogStash::Event.new
                  new_event.set("message", "ALERT FREQ -- rule id:" + f_rule['id'].to_s + " -- count " + v_cour.to_s + "events for 60s -- VARIA morest : " + varia_cour.to_s + "(varia courant) > " + @db_freq[f_rule['id']]['varia_avg'].to_s + "(varia global)")
                  new_event.set("type", "alert_freq")
                  new_event.set("ruleid", f_rule['id'].to_s)
                  new_event.set("time", tnow.to_s)
                end
              end
              @db_freq[f_rule['id']]['status_acces'] = true
            end
          end
        end
      end
    end
    ##### NOT CREATE ALERTE ON EVENT BECAUSE EVENT MAYBE NOT ORIGIN FREQ INCREASE ###
    ######################
                
    filter_matched(event)
  end
  ########## LOAD/REFRESH/SAVE CONF & DB ################
  private
  def load_rules_freq
    if !File.exists?(@conf_freq)
      @logger.warn("DB file read failure, stop loading", :path => @conf_freq)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_freq
    if not tmp_hash == @hash_conf_freq
      @hash_conf_freq = tmp_hash
      tmp_db = JSON.parse( IO.read(@conf_freq, encoding:'utf-8') ) 
      unless tmp_db.nil?
        if tmp_db['rules'].is_a?(Array)
          @freq_rules = tmp_db['rules']
          #CREATE DB with ID
          for rulex in @freq_rules
            if @db_freq[rulex['id']].nil?
              @db_freq[rulex['id']]={}
              @db_freq[rulex['id']]['num_time']=0
              @db_freq[rulex['id']]['count_cour']=0
              @db_freq[rulex['id']]['reset_time']=0
              @db_freq[rulex['id']]['status_acces']=true
            end
          end
        end
      end
      @logger.info("loading/refreshing REFERENCES conf rules")
    end
  end
  def load_db_pattern
    if !File.exists?(@db_pattern)
      @logger.warn("DB file read failure, stop loading", :path => @db_pattern)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @db_pattern
    if not tmp_hash == @hash_dbpattern
      @hash_dbpattern = tmp_hash
      File.readlines(@db_pattern).each do |line|
        elem1, elem2 = line.split(/=>>/)
        elem2.delete!("\n")
        @pattern_db[elem1] = elem2
      end
    end
  end
  def load_db_ref
    if !File.exists?(@db_ref)
      @logger.warn("DB file read failure, stop loading", :path => @db_ref)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @db_ref
    if not tmp_hash == @hash_dbref
      @hash_dbref = tmp_hash
      tmp_db = JSON.parse( IO.read(@db_ref, encoding:'utf-8') ) 
      unless tmp_db.nil?
        #TODO
      end
      @logger.info("loading/refreshing REFERENCES DB")
    end
    #CONF    
    if !File.exists?(@conf_ref)
      @logger.warn("DB file read failure, stop loading", :path => @conf_ref)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_ref
    if not tmp_hash == @hash_conf_ref
      @hash_conf_ref = tmp_hash
      tmp_db = JSON.parse( IO.read(@conf_ref, encoding:'utf-8') ) 
      unless tmp_db.nil?
        unless tmp_db['rules'].nil?
          if tmp_db['rules'].is_a?(Array)
            @ref_rules= tmp_db['rules']
          end
        end
      end
      @logger.info("loading/refreshing REFERENCES conf rules")
    end
  end
  def load_conf_rules_sig
    if !File.exists?(@conf_rules_sig)
      @logger.warn("DB file read failure, stop loading", :path => @conf_rules_sig)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_rules_sig
    if not tmp_hash == @hash_conf_rules_sig
      @hash_conf_rules_sig = tmp_hash
      @sig_db = JSON.parse( IO.read(@conf_rules_sig, encoding:'utf-8') ) 
      @sig_db_array.clear
      @sig_db_array_false.clear
      keyF = Array.new
      keyT = Array.new
      #order sig_db by type (1 or 2)
      if @sig_db['rules'].is_a?(Array)
        tmp = *@sig_db['rules']
        j=0
        (0..@sig_db['rules'].length-1).each do |i|
          @sig_db['rules'][i].each do |nkey,nval|
            if nval['type'].is_a?(Numeric)
              if nval['type'] == 2
                #puts 'find at'+i.to_s+' -> '+j.to_s+' -- '+tmp[i-j].to_s
                tmp=tmp.insert(-1,tmp.delete_at(i-j))
                j=j+1
                break
              end
            end
          end
        end
        #create Field True & false
        @sig_db['rules'] = *tmp
        for rule in tmp
          keyF.clear
          keyT.clear
          rule.each do |nkey,nval|
            if nval.has_key?('false')
              keyF.push(nkey)
            else
              keyT.push(nkey)
            end
          end
          @sig_db_array.push([*keyT])
          @sig_db_array_false.push([*keyF])
          @sig_db_array_len=@sig_db_array.length-1
        end
        keyF.clear
        keyT.clear
      end
      @logger.info("loading/refreshing SIG conf rules")
    end
  end
  def load_conf_rules_note
    if !File.exists?(@conf_rules_note)
      @logger.warn("DB file read failure, stop loading", :path => @conf_rules_note)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_rules_note
    if not tmp_hash == @hash_conf_rules_note
      @hash_conf_rules_note = tmp_hash
      tmp_db = JSON.parse( IO.read(@conf_rules_note, encoding:'utf-8') ) 
      unless tmp_db.nil?
        unless tmp_db['rules'].nil?
          if tmp_db['rules'].is_a?(Array)
            @note_db = tmp_db['rules']
          end
        end
      end
      @logger.info("loading/refreshing NOTE conf rules")
    end
  end
  def load_conf_ioc
    if !File.exists?(@conf_ioc)
      @logger.warn("DB file read failure, stop loading", :path => @conf_ioc)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_ioc
    if not tmp_hash == @hash_conf_ioc
      @hash_conf_ioc = tmp_hash
      @ioc_rules = JSON.parse( IO.read(@conf_ioc, encoding:'utf-8') )
      @logger.info("loading/refreshing IOC conf rules")
    end
  end
  def load_db_ioc
    #if one file change reload all file
    change = false
    @db_ioc.sort.each do |f|
      if !File.exists?(f)
        @logger.warn("DB file read failure, stop loading", :path => f)
        return
      end
      tmp_hash = Digest::SHA256.hexdigest File.read f
      if @hash_dbioc[f]
        if not tmp_hash == @hash_dbioc[f]
         #load
         @hash_dbioc[f] = tmp_hash
         change = true
        end
      else
        #load
        @hash_dbioc[f] = tmp_hash
        change = true
      end
    end
    if change == true
      @ioc_db = {}
      @db_ioc.sort.each do |f|
        db_tmp = JSON.parse( IO.read(f, encoding:'utf-8') )
        @ioc_db = @ioc_db.merge(db_tmp) {|key, first, second| first.is_a?(Array) && second.is_a?(Array) ? first | second : second }
      end
      @logger.info("loading/refreshing DB IOC file(s)")
    end
  end
  def load_conf_nv 
    if !File.exists?(@conf_nv)
      @logger.warn("DB file read failure, stop loading", :path => @conf_nv)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_nv
    if not tmp_hash == @hash_conf_nv
      @hash_conf_nv = tmp_hash
      @nv_rules = JSON.parse( IO.read(@conf_nv, encoding:'utf-8') ) 
      if @nv_rules['rules']
        for rule in @nv_rules['rules']
          if not @nv_db[rule.to_s]
            @nv_db[rule.to_s] = []
          end
        end
      end
      @logger.info("refreshing DB NewValue file")
    end
  end
  def save_db_nv
    File.open(@db_nv,"w+") do |f|
      f.write(JSON.pretty_generate(@nv_db))
    end
  end
  def save_db_ioclocal
    File.open(@file_save_localioc,"w+") do |f|
      f.write(JSON.pretty_generate(@ioc_db_local))
    end
  end
  def load_conf_fp
  #load db conf fp
    if !File.exists?(@conf_fp)
      @logger.warn("DB file read failure, stop loading", :path => @conf_fp)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_fp
    if not tmp_hash == @hash_conf_fp
      @hash_conf_fp = tmp_hash
      @fp_rules = JSON.parse( IO.read(@conf_fp, encoding:'utf-8') )
    end
  end
  def load_db_dropfp
    #load fp
    if !File.exists?(@db_dropfp)
      @logger.warn("DB file read failure, stop loading", :path => @db_dropfp)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @db_dropfp
    if not tmp_hash == @hash_dropfp
      @hash_dropfp = tmp_hash
      @fp_db = JSON.parse( IO.read(@db_dropfp, encoding:'utf-8') )
    end
  end
  def load_db_drop
  #load drop db
    if !File.exists?(@db_drop)
      @logger.warn("DB file read failure, stop loading", :path => @db_drop)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @db_drop
    if not tmp_hash == @hash_dropdb
      @hash_dropdb = tmp_hash
      @drop_db = JSON.parse( IO.read(@db_drop, encoding:'utf-8') )
    end
  end
  #clean db special
  def clean_db_sigfreq(date)
    @sig_db_freq.each do |nkey,nval|
      if nval[delay] < date
        @sig_db_freq.delete(nkey)
      end
    end
  end
end
