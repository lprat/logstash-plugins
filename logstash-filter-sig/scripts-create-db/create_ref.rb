#code for create DB REF for use in logstash SIG plugin (function ref)
#author: lionel.prat9@gmail.com

require 'elasticsearch'
require 'json'
require 'simhash'

##############################
#func nested_hash_value is find on http://stackoverflow.com/questions/8301566/find-key-value-pairs-deep-inside-a-hash-containing-an-arbitrary-number-of-nested
def nested_hash_value(obj,key)
  if obj.respond_to?(:key?) && obj.key?(key)
    obj[key]
  elsif obj.respond_to?(:each)
    r = nil
    obj.find{ |*a| r=nested_hash_value(a.last,key) }
    r
  end
end
##############################
stop = false

#load rules
rules={}
if ARGV[0]
  if !File.exists?(ARGV[0])
    @logger.warn("File RULES not exist", :path => ARGV[0])
    exit(0)
  else
    tmp_db = JSON.parse( IO.read(ARGV[0], encoding:'utf-8') ) 
    unless tmp_db.nil?
      unless tmp_db['rules'].nil?
        if tmp_db['rules'].is_a?(Array)
          rules= tmp_db['rules']
        end
      end
    end
  end
else
  stop = true
end


#load pattern
pattern_db = {}
if ARGV[1]
#load rules
  if !File.exists?(ARGV[1])
    @logger.warn("File PATTERN DB not exist", :path => ARGV[1])
    exit(0)
  else
  File.readlines(ARGV[1]).each do |line|
    elem1, elem2 = line.split(/=>>/)
    elem2.delete!("\n")
    pattern_db[elem1] = elem2
  end
  end
else
  stop = true
end

#create connexion ES
if ARGV[2]      
  @client = Elasticsearch::Client.new url: ARGV[2], timeout: 600,
     transport_options: { ssl: { verify: false } }
  #verify connection
  begin
    res=@client.info
  rescue
    puts 'error connexion to ES'
    exit (0)
  end
else
  stop = true
end

#usage
if ARGV.empty? or stop
  puts "Usage: create_ref.rb conf_ref.json pattern.db  ES_URI(ex: https://user:secret@localhost:9200) [INDEX_NAME:logstash-*] [DEFAUT_NOTE_FILE:note_ref_defaut.json]"
  exit 1
end

#outpout file:
output_file='reference.json'
#choice option index name
if ARGV[3]      
  index_name = ARGV[3].to_s
else
  index_name = "logstash-*"
end

#choice option file contains note
if ARGV[4]      
  note_file = ARGV[4].to_s
else
  note_file = "note_ref_defaut.json"
end
#note_db => {"NOTE_ENCODING": 0.25, "NOTE_ASCII": 0.25, "DEFAULT_NOTE": 2, "NOTE_UNIQ_REDUC": 0.1...}
note_db = {}
if !File.exists?(note_file)
  @logger.warn("File NOTE DB not exist", :path => note_file)
  exit(0)
else
  note_db = JSON.parse( IO.read(note_file, encoding:'utf-8') ) 
end
#rules[ {"pivot_field":{field1:'value'},{field2:'value'}, "list_sig": [fieldx,fieldy,...], "relation_min": 10, "simhash_size": 16, "simhash_use_size": 14, "id": 200X} ] 

ref_db = {}   
#create db rule by rule
for rule in rules
  #create reference in db with ID of rule
  ref_db[rule['id']] = {}
  #sav field not uniq for use to relation/link
  tmp_field_notuniq = []
  #create search with pivot field and value, with aggregation on each field
  #create pivot
  query_pivot = []
  rule['pivot_field'].each do |fieldp,valp|
    # exist field query: { "exists":{ "field": "src_ip" } }
    tmp_query = {"query": { "match": { } } }
    tmp_query["query"]["match"][fieldp] = {"query": valp, "type": "phrase"}
    query_pivot.push(tmp_query)
  end
  for fieldx in rule['list_sig']
    ref_db[rule['id']][fieldx] = {}
    #pivot => {"query": {"match": {field_name: {"query": field_value,"type": "phrase"}}},
    #get mapping info for field for choice use ".raw" or no
    res=client.indices.get_field_mapping index: index_name, field: fieldx
    type_field=nested_hash_value(res,'type')
    #https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
    field_name=fieldx
    #use raw for string
    #problem on array hash... by exemple sig_detected
    #if not ['ip', 'binary', 'date', 'boolean', 'long', 'integer', 'short', 'byte', 'double', 'float'].include?(type_field.to_s)
    ref_db[rule['id']][fieldx]['TYPE'] = type_field.to_s
    if ['boolean', 'long', 'integer', 'short', 'byte', 'double', 'float'].include?(type_field.to_s)
      #method for number
      res=@client.search index: index_name, size: 0, search_type: 'count', body: {"query": { "filtered": { "filter": { "bool": { "must": query_pivot } } } }, "aggregations": { "SP": { "terms": { "field": field_name, "size": 0, "order": {"_count": "desc"}}} }  }
      #res['aggregations']['SP']['buckets'].length.to_s
      #res["hits"]["total"].to_s
      #check uniq term if more than 1% difference res["hits"]["total"]*0.01) == 1% && if 1% > res['aggregations']['SP']['buckets'].length then UNIQ else NOT UNIQ END
      if (res['aggregations']['SP']['buckets'].length >= 1) and (res['aggregations']['SP']['buckets'].length>(res["hits"]["total"]*0.01)
        #not uniq
        ref_db[rule['id']][fieldx]['Uniq_value'] =  false
      else
        #uniq
        ref_db[rule['id']][fieldx]['Uniq_value'] = true
      end
      if res['aggregations']['SP']['buckets'].length >= 1 and 20 <= res['aggregations']['SP']['buckets'].length
        ref_db[rule['id']][fieldx]['LIST_VALUE'] = []
        for hash_aggr in res['aggregations']['SP']['buckets']
          ref_db[rule['id']][fieldx]['LIST_VALUE'].push(*hash_aggr['key'])
        end
      end
      ref_db[rule['id']][fieldx]['ENCODING'] = []
      ref_db[rule['id']][fieldx]['LEN_MAX'] = 0
      ref_db[rule['id']][fieldx]['LEN_MIN']= 9999999999
      count_avg = 0
      len_avg = 0
      evennumber=false
      noevennumber=false
      ref_db[rule['id']][fieldx]['LEN_AVG_PRCT'] = 20 # +/- 20% of LEN_AVG for accept
      ref_db[rule['id']][fieldx]['REGEXP'] = []
      ref_db[rule['id']][fieldx]['REGEXP_MIN'] = []
      for hash_aggr in res['aggregations']['SP']['buckets']
        #analyz entry by entry:  {"key"=>"XXX", "doc_count"=>NNN}
        #collect encoding -> float,
        ref_db[rule['id']][fieldx]['ENCODING'].push(*hash_aggr['key'].class.to_s) unless ref_db[rule['id']][fieldx]['ENCODING'].include?(hash_aggr['key'].class.to_s)
        #collect len info
        ref_db[rule['id']][fieldx]['LEN_MAX'] = hash_aggr['key'].to_i if ref_db[rule['id']][fieldx]['LEN_MAX'] < hash_aggr['key'].to_i
        ref_db[rule['id']][fieldx]['LEN_MIN'] = hash_aggr['key'].to_i if ref_db[rule['id']][fieldx]['LEN_MIN'] > hash_aggr['key'].to_i
        count_avg = count_avg + hash_aggr['doc_count'].to_i
        len_avg = len_avg + (hash_aggr['doc_count'].to_i * hash_aggr['doc_count'].to_i)
        #check EVEN number or not (length for string)
        if hash_aggr['doc_count'].to_i.even?
          evennumber = true
        else
          noevennumber = true
        end
        #check pattern on aggr value
        rlist = []
        pattern_db.each do |key, value|
          match = Regexp.new(value, nil, 'n').match(hash_aggr['key'].to_s)
          if not match.nil?
            rlist << key
          end
        end
        #create list regexp min
        if ref_db[rule['id']][fieldx]['REGEXP_MIN'].empty?
          ref_db[rule['id']][fieldx]['REGEXP_MIN'] = rlist
        else
          intersec = ref_db[rule['id']][fieldx]['REGEXP_MIN'] & rlist
          ref_db[rule['id']][fieldx]['REGEXP_MIN'] = intersec
        end
        #create regexp list
        ref_db[rule['id']][fieldx]['REGEXP'].push(*rlist.join("::")) unless ref_db[rule['id']][fieldx]['REGEXP'].include?(rlist.join("::"))
      end
      ref_db[rule['id']][fieldx]['LEN_AVG'] = (len_avg / count_avg).to_i if count_avg != 0
      if evennumber && noevennumber
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 0
      elsif evennumber
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 1
      elsif noevennumber
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 2
      else
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 0
      end
      note_db.each do |nkey, nval|
        if nkey.to_s != 'NOTE_DEFAULT' and nkey.to_s != 'NOTE_UNIQ_REDUC'
          ref_db[rule['id']][fieldx][nkey] = nval
          #if field is uniq then reduce note possible
          ref_db[rule['id']][fieldx][nkey] = ref_db[rule['id']][fieldx][nkey] - note_db['NOTE_UNIQ_REDUC'] if ref_db[rule['id']][fieldx]['Uniq_value']
        end
      end
    else
      if 'string' == type_field.to_s
        field_name=fieldx+'.raw'
      end
      #method for string
      res=@client.search index: index_name, size: 0, search_type: 'count', body: {"query": { "filtered": { "filter": { "bool": { "must": query_pivot } } } }, "aggregations": { "SP": { "terms": { "field": field_name, "size": 0, "order": {"_count": "desc"}}} }  }
      #res['aggregations']['SP']['buckets'].length.to_s
      #res["hits"]["total"].to_s
      #check uniq term if more than 1% difference res["hits"]["total"]*0.01) == 1% && if 1% > res['aggregations']['SP']['buckets'].length then UNIQ else NOT UNIQ END
      if (res['aggregations']['SP']['buckets'].length >= 1) and (res['aggregations']['SP']['buckets'].length>(res["hits"]["total"]*0.01)
        #not uniq
        ref_db[rule['id']][fieldx]['Uniq_value'] =  false
        tmp_field_notuniq.push(*fieldx)
      else
        #uniq
        ref_db[rule['id']][fieldx]['Uniq_value'] = true
      end
      if res['aggregations']['SP']['buckets'].length >= 1 and 20 <= res['aggregations']['SP']['buckets'].length
        ref_db[rule['id']][fieldx]['LIST_VALUE'] = []
        for hash_aggr in res['aggregations']['SP']['buckets']
          ref_db[rule['id']][fieldx]['LIST_VALUE'].push(*hash_aggr['key'])
        end
      end
      ref_db[rule['id']][fieldx]['ENCODING'] = []
      ref_db[rule['id']][fieldx]['LEN_MAX'] = 0
      ref_db[rule['id']][fieldx]['LEN_MIN']= 9999999999
      count_avg = 0
      len_avg = 0
      evennumber=false
      noevennumber=false
      ref_db[rule['id']][fieldx]['LEN_AVG_PRCT'] = 20 # +/- 20% of LEN_AVG for accept
      ref_db[rule['id']][fieldx]['REGEXP'] = []
      ref_db[rule['id']][fieldx]['REGEXP_MIN'] = []
      for hash_aggr in res['aggregations']['SP']['buckets']
        #analyz entry by entry:  {"key"=>"XXX", "doc_count"=>NNN}
        #collect encoding
        ref_db[rule['id']][fieldx]['ENCODING'].push(*hash_aggr['key'].encoding.to_s) unless ref_db[rule['id']][fieldx]['ENCODING'].include?(hash_aggr['key'].encoding.to_s)
        #collect len info
        ref_db[rule['id']][fieldx]['LEN_MAX'] = hash_aggr['key'].length if ref_db[rule['id']][fieldx]['LEN_MAX'] < hash_aggr['key'].length
        ref_db[rule['id']][fieldx]['LEN_MIN'] = hash_aggr['key'].length if ref_db[rule['id']][fieldx]['LEN_MIN'] > hash_aggr['key'].length
        count_avg = count_avg + hash_aggr['doc_count'].to_i
        len_avg = len_avg + (hash_aggr['doc_count'].to_i * hash_aggr['doc_count'].length)
        #check EVEN number or not (length for string)
        if hash_aggr['doc_count'].length.even?
          evennumber = true
        else
          noevennumber = true
        end
        #check pattern on aggr value
        rlist = []
        pattern_db.each do |key, value|
          match = Regexp.new(value, nil, 'n').match(hash_aggr['key'].to_s)
          if not match.nil?
            rlist << key
          end
        end
        #create list regexp min
        if ref_db[rule['id']][fieldx]['REGEXP_MIN'].empty?
          ref_db[rule['id']][fieldx]['REGEXP_MIN'] = rlist
        else
          intersec = ref_db[rule['id']][fieldx]['REGEXP_MIN'] & rlist
          ref_db[rule['id']][fieldx]['REGEXP_MIN'] = intersec
        end
        #create regexp list
        ref_db[rule['id']][fieldx]['REGEXP'].push(*rlist.join("::")) unless ref_db[rule['id']][fieldx]['REGEXP'].include?(rlist.join("::"))
      end
      ref_db[rule['id']][fieldx]['LEN_AVG'] = (len_avg / count_avg).to_i if count_avg != 0
      if evennumber && noevennumber
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 0
      elsif evennumber
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 1
      elsif noevennumber
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 2
      else
        ref_db[rule['id']][fieldx]['LEN_EVENorUNEVENnum'] = 0
      end
      #create note for field
      note_db.each do |nkey, nval|
        if nkey.to_s != 'NOTE_DEFAULT' and nkey.to_s != 'NOTE_UNIQ_REDUC'
          ref_db[rule['id']][fieldx][nkey] = nval
          #if field is uniq then reduce note possible
          ref_db[rule['id']][fieldx][nkey] = ref_db[rule['id']][fieldx][nkey] - note_db['NOTE_UNIQ_REDUC'] if ref_db[rule['id']][fieldx]['Uniq_value']
        end
      end
      #check result & analyz & create reference for field
    end
  end
  #leave of aggr field
  #create link information
  #1- find if field not uniq in all event or some optionnal (& determine)
  count1=@client.search index: index_name, size: 0, search_type: 'count', body: {"query": { "filtered": { "filter": { "bool": { "must": query_pivot } } } }  }
  # two type field: optionnal present and always present
  field_option = []
  field_always = []
  for fieldy in tmp_field_notuniq
    # exist field query: { "exists":{ "field": "src_ip" } }
    tmp_query = []
    query_pivot.each{|e| tmp_query  << e.dup}
    tmp_filter = { "exists":{ "field": fieldy.to_s } }
    tmp_query.push(tmp_filter)
    count2=@client.search index: index_name, size: 0, search_type: 'count', body: {"query": { "filtered": { "filter": { "bool": { "must": tmp_query } } } }  }
    if ((count1["hits"]["total"]+(count1["hits"]["total"]*0.01)) >= count2["hits"]["total"]) and ((count1["hits"]["total"]-(count1["hits"]["total"]*0.01)) <= count2["hits"]["total"])
      # always present
      field_always.push(*fieldy)
    else
      #optionnal present
      field_option.push(*fieldy)
    end
  end
  #2- create link with all possibility field
  combis = []
  for n in 1..field_option.length
    combis.push(field_option.combination(n).to_a)
  end
  combis=combis.flatten(1)
  if combis.empty?
    # use field_alaways if option is empty
    combis.push(field_always)
  else
    for combi in combis
      for fa in field_always
        combi.push(fa)
      end
    end
  end
  #3- order value (classed by field name) for create simhash
  simhash_combi = {}
  for combi in combis
  tmp_filter = { "exists":{ "field": fieldy.to_s } }
    tmp_query = []
    query_pivot.each{|e| tmp_query  << e.dup}
    #create filter with field combinaison
    for field_choice in combi
      tmp_filter = { "exists":{ "field": field_choice.to_s } }
      tmp_query.push(tmp_filter)
    end
    res_link=@client.search index: index_name, size: 0, body: {"query": { "filtered": { "filter": { "bool": { "must": tmp_query } } } }  }
    #use scroll for view all event -- duration max 5minutes => '5m'
    #verify you rigth to access scroll!!!! (shield/elasticguard)
    r=client.search index: 'logstash-*', scroll: '5m', size: 10000, body: {"query": { "filtered": { "filter": { "bool": { "must": tmp_query } } } } }
    # Call the `scroll` API until empty results are returned
    while r = client.scroll(scroll_id: r['_scroll_id'], scroll: '5m') and not r['hits']['hits'].empty? do
      for rfields in r['hits']['hits']
        simhash_tmp=""
        for field_choice in combi.sort
          #create simhash with order by field name
          simhash_tmp=simhash_tmp+rfields["_source"][field_choice.to_s].to_s.force_encoding('iso-8859-1').encode('utf-8')
        end
        simhash_complet = simhash_tmp.simhash(:hashbits => rule["simhash_size"]).to_s 
        if simhash_combi[simhash_complet]
          simhash_combi[simhash_complet] = simhash_combi[simhash_complet] + 1
        else
          simhash_combi[simhash_complet] = 1
        end
      end
    end
    #delete scroll
  end
  ref_db[rule['id']]['NOTE_DEFAULT'] = note_db['NOTE_DEFAULT']
  ref_db[rule['id']]['relation_value_fix'] = simhash_combi 
end
@client.indices.clear_cache()
#create json file
File.open(@file_save_localioc,"w+") do |f|
      f.write(JSON.pretty_generate(ref_db))
end

            #{ 'ID20XXXX': {
            #                                                                      'field': {
            #                                                                                 'TYPE': 'Array|Int|String|...', # not use mapping, because bad way , regexp can used for this
            #                                                                                 'Uniq_value': true or false, #define if value is random => true << OK AGG
            #                                                                                 'NOTE_UNIQ_REDUC': 0.1 # for reduce note if match on uniq fueld
            #                                                                                 'LIST_VALUE': ['value_possible1','value_possible2','value_possibleX'], << OK AGG
            #                                                                                 'NOTE_LISTV': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'ENCODING': true or false, # value contains than ascii caratere << OK AGG
            #                                                                                 'NOTE_ENCODING': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'LEN_MAX': numeric_value, << OK AGG
            #                                                                                 'NOTE_LEN': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'LEN_MIN': numeric_value, << OK AGG
            #                                                                                 'LEN_AVG': numeric_value, << OK AGG
            #                                                                                 'LEN_AVG_PRCT': pourcent for AVG, << OK AGG
            #                                                                                 'NOTE_LEN_AVG': 0.1 # note between 0.x and 4 default 0.1
            #                                                                                 'LEN_EVENorUNEVENnum': numeric_value, #even num = 1;uneven num = 2; unknown/undefine = 0 << OK AGG
            #                                                                                 'NOTE_LEN_EVEN': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'REGEXP_MIN': [], << OK AGG
            #                                                                                 'NOTE_REGEXP_MIN': 0.25 # note between 0.x and 4 default 0.25
            #                                                                                 'REGEXP': [] << OK AGG
            #                                                                                 'NOTE_REGEXP': 0.25 # note between 0.x and 4 default 0.25
            #                                                                               } ,
            #                                                                      #relation value_fix contains list of value of field not unique (random)
            #                                                                      # by exemple fld1: '1'; fld2: 'blabla';fld3: '10.10.10.10'
            #                                                                      # create LIST simhash value and attention to order field
            #                                                                      # you can optimiz with simhash - end if earn place memory
            #                                                                      # important you count SIMHASH:COUNT for use COUNT if very little score => suspect [use conf -> relation_min]
            #                                                                      'relation_value_fix": {'SIMHASH1':COUNTX,'SIMHASH2':COUNTY,'SIMHASH3':COUNTX},
            #                                                                      'NOTE_DEFAULT': 2# note between 0.x and 4 default 2
            #                                                                      }}}
