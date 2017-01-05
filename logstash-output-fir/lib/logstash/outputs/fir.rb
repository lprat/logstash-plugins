# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "json"
require "uri"
require "manticore"
require "time"
require "erb"

# An example output that does nothing.
class LogStash::Outputs::Fir < LogStash::Outputs::Base
  config_name "fir"
  
  # URL to use
  config :url_api_fir, :validate => :string, :required => :true, :default => "https://127.0.0.1:8000/api/"
  #refresh remote information FIR - get closed information & new ticket manual & artefacts db
  config :refresh_interval_remote, :validate => :number, :default => 3600

  # Custom headers to use
  # format is `headers => ["X-My-Header", "%{host}"]`
  #REPLACE 0000000000000000000000000000 by your token
  config :headers, :validate => :hash, :required => :true, :default => {"Authorization" => "Token 0000000000000000000000000000", "Content-Type" => "application/json"}
  #use insecure mode change by '{ verify: :disable }'
  config :ssl_options, :validate => :string, :default => "{ :verify => :disable }"
  
  #template body & subject ERB
  #template for new alert
  config :template_new, :validate => :path, :default => "/etc/logstash/db/template_new.erb"
  #template for update alert
  config :template_update, :validate => :path, :default => "/etc/logstash/db/template_update.erb"
  #template subject for new alert
  config :subj_template_new, :validate => :path, :default => "/etc/logstash/db/subject_template_new.erb"
  #template subject for update alert
  config :subj_template_update, :validate => :path, :default => "/etc/logstash/db/subject_template_update.erb"
  #MATCH CONFIGURATION:
  config :conffile, :validate => :string, :default => "/etc/logstash/db/conf_fir.json"
  #need: filter + first identification in sujet + second identification for alert exist in body + optionnal change template
  #Configuration -- format HASH
  #rules [
  # {
  #   filters: {},
  #   subject_filter: 'name_field_in_event', # by example field src_ip
  #   subject_filter_prefix: 'string must match.. before content of field subject filter' #optionnal
  #   subject_filter_sufix: 'string must match.. after content of field subject filter' #optionnal
  #   body_filter: 'name_field_in_event',   # by example field fingerprint
  #   body_filter_prefix: 'string must match.. before content of field body filter' #optionnal
  #   body_filter_sufix: 'string must match.. after content of field body filter' #optionnal
  #   severity_add: 'name_field_in_event', # by example field sig_detected_note !!optionnal!!
  #   fields_create: {'name' => value, '' => value} # !!!REQUIRE FOR CREATE: "actor" = 6 & "category" & "confidentiality" & "detection" & "plan" & "is_starred" & "is_major" & "is_incident" & "concerned_business_lines"
  #   template_new_sujet: 'path', #optionnal
  #   template_new_body: 'path', #optionnal
  #   template_up_sujet: 'path', #optionnal
  #   template_up_body: 'path', #optionnal
  # }
  #]
  
  # this setting will indicate how frequently
  # (in seconds) logstash will check the db file for updates.
  config :refresh_interval, :validate => :number, :default => 3600
  
  #choice in FIR for subject and body and severity -- API REST 
  config :subject_field, :validate => :string, :default => "subject"
  config :body_field, :validate => :string, :default => "description"
  config :severity_field, :validate => :string, :default => "severity"
  config :status_field, :validate => :string, :default => "status"
  
  concurrency :single
  
  public
  def register
    @fir_conf = []
    @incidents_db = {}
    @client = Manticore::Client.new(ssl: eval(@ssl_options))
    @logger.info("FIR Configuration -- Loading...")
    @hash_file = ""
    @load_statut = false
    load_db
    @load_statut = true
    @logger.info("finish")
    #file load template
    @logger.info("FIR templates -- Loading...")
    @template_data_n = ""
    @template_data_u = ""
    @template_subj_n = ""
    @template_subj_u = ""
    if File.file?(@template_new) && File.file?(@template_update) && File.file?(@subj_template_new) && File.file?(@subj_template_update)
      @template_data_n = File.read(@template_new)
      @template_data_u = File.read(@template_update)
      @template_subj_n = File.read(@subj_template_new)
      @template_subj_u = File.read(@subj_template_update)
    else
      @logger.error("FIR templates not found!")
      exit -1
    end
    @logger.info("finish")
    @next_refresh = Time.now + @refresh_interval
    @load_statut_r = false
    @logger.info("FIR get incident DB -- Loading...could take a sometime...")
    load_incidents
    @logger.info("finish")
    @load_statut_r = true
    @next_refresh = Time.now + @refresh_interval
    @next_refresh_remote = Time.now + @refresh_interval_remote
    @token_create=true
  end # def register

  public
  def multi_receive(events)
    events.each {|event| receive(event)}
  end

  def receive(event)
    tnow = Time.now
    #refresh DB & conf
    if @next_refresh < tnow
      if @load_statut == true
        @load_statut = false
        load_db
        if File.file?(@template_new) && File.file?(@template_update)
          @template_data_n = File.read(@template_new)
          @template_data_u = File.read(@template_update)
        end
        @next_refresh = tnow + @refresh_interval
        @load_statut = true
      end
    end
    if @next_refresh_remote < tnow
      if @load_statut_r == true
        @load_statut_r = false
        @logger.info("FIR refresh incident DB -- could take a sometime...")
        load_incidents
        @next_refresh_remote = tnow + @refresh_interval_remote
        @load_statut_r = true
      end
    end
    sleep(1) until @load_statut_r
    sleep(1) until @load_statut
    #verify db & conf is OK!
    if @fir_conf.is_a?(Array) and not @incidents_db.nil?
      #check filter: {'field_name': [] or ""  -- if field event is numerci, the code change to string
      #match one regexp on field event use string value "regexp" 
      #match multi regexp (for array type) on field event use array type: [regex1,regexp2,...] for match ok all regexp must matched one time
      # }
      for rule in @fir_conf
        #get key in rule: fields
        eventK = event.to_hash.keys
        inter = rule['filters'].keys & eventK
        #check if fields rule present in event
        if inter.length == rule['filters'].keys.length
          #ok field present - check filter
          #check field by field
          sig_add = {}
          check_sig=false
          for kfield in inter
            check_sig=false
            # field X -- check type
            if event.get(kfield).is_a?(Array)
              #array type
              # if rule value regexp is Array?
              if rule['filters'][kfield].is_a?(Array)
                for regexp in rule['filters'][kfield]
                  check_sig=false
                  for elem in event.get(kfield)
                    match = Regexp.new(regexp, nil, 'n').match(elem.to_s)
                    if not match.nil?
                      check_sig=true
                      break
                    end
                  end
                  break unless check_sig
                end
              else
                #rule not array
                for elem in event.get(kfield)
                  match = Regexp.new(rule['filters'][kfield], nil, 'n').match(elem.to_s)
                  if not match.nil?
                    check_sig=true
                    break
                  end
                end
              end
            else
              #other type
              # if rule value regexp is Array?
              if rule['filters'][kfield].is_a?(Array)
                #array
                for regexp in rule['filters'][kfield]
                  match = Regexp.new(regexp, nil, 'n').match(event.get(kfield).to_s)
                  if not match.nil?
                    sig_add[kfield.to_s]="Regexp found #{match}"
                    check_sig=true
                    next
                  end
                  break unless check_sig
                end
              else
                #other
                match = Regexp.new(rule['filters'][kfield], nil, 'n').match(event.get(kfield).to_s)
                if not match.nil?
                  check_sig=true
                  next
                end
              end
            end
            break unless check_sig
          end
          if check_sig
            #filter matched
            #stat of exist alert
            check_if_create=true
            #verify filter present subject_filter && body_filter
            if not event.get(rule['subject_filter'].to_s).nil? and not event.get(rule['body_filter'].to_s).nil?
              #ok
              #not write in same time for avoid corruption db
              #check in incident db if alert exist
              for incident in @incidents_db["results"]
                #verify if incident is Open or Close -- just check incident open
                next if not incident[@status_field].to_s == "O"
                #verify if filter subject present in incident DB
                next if not incident[@subject_field].include?(rule['subject_filter_prefix'].to_s+event.get(rule['subject_filter'].to_s).to_s+rule['subject_filter_sufix'].to_s)
                #verify if filter body present in incident DB
                check_if_create=false
                #if body match, break, is ok -> created and updated
                break if incident[@body_field].include?(rule['body_filter_prefix'].to_s+event.get(rule['body_filter'].to_s).to_s+rule['body_filter_sufix'].to_s)
                #if body no match, then update
                #UPDATE
                sleep(1) until @token_create
                @token_create=false
                #update incident
                #change severity if option not empty
                if rule['severity_add'] and (event.get(rule['severity_add'].to_s).is_a?(String) or event.get(rule['severity_add'].to_s).is_a?(Numeric))
                  if incident["severity"] < event.get(rule['severity_add'].to_s).to_i
                    incident[@severity_field] = event.get(rule['severity_add'].to_s).to_i
                  end
                end
                if not rule['template_up_sujet'].nil? and not rule['template_up_sujet'].empty?
                  incident[@subject_field] = ERB.new(rule['template_up_sujet']).result(binding)
                else
                 incident[@subject_field] = ERB.new(@template_subj_u).result(binding)
                end
                #keep old content
                if not rule['template_up_body'].nil? and not rule['template_up_body'].empty?
                  incident[@body_field] = ERB.new(rule['template_up_body']).result(binding) + incident[@body_field]
                else
                  incident[@body_field] = ERB.new(@template_data_u).result(binding) + incident[@body_field]
                end
                url = @url_api_fir + "incidents/" + body["id"].to_s
                begin
                  response = @client.patch(url, :body => body.to_json, :headers => @headers)
                  if response.code < 200 and response.code > 299
                    log_failure(
                      "Encountered non-200 HTTP code #{200}",
                      :response_code => response.code,
                      :url => url,
                      :event => event)
                  end
                rescue
                  @logger.warn("ERROR SEND:", :string => body.to_json)
                end
                #end - give token
                @token_create=true
                #break loop check_if_create is false, stop process => created and updated OK
                break
              end
              if check_if_create and rule['fields_create'].is_a?(Hash)
                #create
                sleep(1) until @token_create
                @token_create=false
                body = {}
                #create base JSON of fir incendent 
                rule['fields_create'].each do |jkey,jval|
                  body[jkey.to_s] = jval
                end
                body["date"] = tnow.strftime("%Y-%m-%dT%H:%M").to_s # format "2016-01-01T00:00" TODO!!! CHOICE GMT
                if rule['severity_add'] and (event.get(rule['severity_add'].to_s).is_a?(String) or event.get(rule['severity_add'].to_s).is_a?(Numeric))
                  if event.get(rule['severity_add'].to_s).to_i < 5
                    body[@severity_field] = event.get(rule['severity_add'].to_s).to_i
                  else
                    body[@severity_field] = 1
                  end
                else
                  body[@severity_field] = 1
                end
                body[@status_field] = "O"
                if not rule['template_new_sujet'].nil? and not rule['template_new_sujet'].empty?
                  body[@subject_field] = ERB.new(rule['template_new_sujet']).result(binding)
                else
                 body[@subject_field] = ERB.new(@template_subj_n).result(binding)
                end
                #keep old content
                if not rule['template_new_body'].nil? and not rule['template_new_body'].empty?
                  body[@body_field] = ERB.new(rule['template_new_body']).result(binding)
                else
                  body[@body_field] = ERB.new(@template_data_n).result(binding)
                end
                url = @url_api_fir+"incidents"
                begin
                  response = @client.post(url, :body => body.to_json, :headers => @headers)
                  if response.code > 200 and response.code < 299
                    #body
                    begin
                      add_inc = JSON.parse(response.body)
                      (@incidents_db["results"] ||= []) << add_inc
                    rescue JSON::ParserError => e
                      @logger.warn("JSON CMD ERROR PARSE:", :string => response.body)
                    end
                  else
                    log_failure(
                      "Encountered non-200 HTTP code #{200}",
                      :response_code => response.code,
                      :url => url,
                      :response => response,
                      :body => body)
                  end
                rescue
                  @logger.warn("ERROR SEND:", :string => body.to_json)
                end
                #end - give token
                @token_create=true
              else
                break # exit of rules check & ok => stop
              end
            end
          end
        end
      end
    end
  end
  
  def close
    @client.close
  end
  
  private
  def load_db
    if !File.exists?(@conffile)
      @logger.warn("Configuration file read failure, stop loading", :path => @conffile)
      return
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conffile
    if not tmp_hash == @hash_file
      @hash_file = tmp_hash
      tmp_conf = JSON.parse( IO.read(@conffile, encoding:'utf-8') ) 
      unless tmp_conf.nil?
        if tmp_conf['rules'].is_a?(Array)
          for rule in tmp_conf['rules']
            if not rule['template_new_sujet'].nil? and not rule['template_new_sujet'].empty? and !File.exists?(rule['template_new_sujet'].to_s)
              @logger.error("Template in configuration file not exist", :path => rule['template_new_sujet'].to_s)
              return
            elsif not rule['template_new_sujet'].nil? and not rule['template_new_sujet'].empty?
              rule['template_new_sujet'] = File.read(rule['template_new_sujet'].to_s)
            end
            if not rule['template_new_body'].nil? and not rule['template_new_body'].empty? and !File.exists?(rule['template_new_body'].to_s)
              @logger.error("Template in configuration file not exist", :path => rule['template_new_body'].to_s)
              return
            elsif not rule['template_new_body'].nil? and not rule['template_new_body'].empty?
              rule['template_new_body'] = File.read(rule['template_new_body'].to_s)
            end
            if not rule['template_up_sujet'].nil? and not rule['template_up_sujet'].empty? and !File.exists?(rule['template_up_sujet'].to_s)
              @logger.error("Template in configuration file not exist", :path => rule['template_up_sujet'].to_s)
              return
            elsif not rule['template_up_sujet'].nil? and not rule['template_up_sujet'].empty?
              rule[template_up_sujet''] = File.read(rule['template_up_sujet'].to_s)
            end
            if not rule['template_up_body'].nil? and not rule['template_up_body'].empty? and !File.exists?(rule['template_up_body'].to_s)
              @logger.error("Template in configuration file not exist", :path => rule['template_up_body'].to_s)
              return
            elsif not rule['template_up_body'].nil? and not rule['template_up_body'].empty?
              rule['template_up_body'] = File.read(rule['template_up_body'].to_s)
            end
            if rule['subject_filter_prefix'].nil?
              rule['subject_filter_prefix'] = ""
            end
            if rule['subject_filter_sufix'].nil?
              rule['subject_filter_sufix'] = ""
            end
            if rule['body_filter_prefix'].nil?
              rule['body_filter_prefix'] = ""
            end
            if rule['body_filter_sufix'].nil?
              rule['body_filter_sufix'] = ""
            end
          end
          @fir_conf = tmp_conf['rules']
        end
      end
      @logger.info("refreshing DB FIR condition file")
    end
  end
  
  # This is split into a separate method mostly to help testing
  def log_failure(message, opts)
    @logger.error("[HTTP Output Failure] #{message}", opts)
  end

  def load_incidents
    # Send the request
    stop_load = true
    incidents_db_tmp = {}
    first = true
    url = @url_api_fir+"incidents?format=json"
    while stop_load
      response = @client.get(url, :headers => @headers)
      #body
      @logger.info("BODY: #{response.body}")
      begin
        field_next = ""
        if first
          incidents_db_tmp = JSON.parse(response.body)
          field_next = incidents_db_tmp["next"]
          first = false
        else
          tmp_db = JSON.parse(response.body)
          incidents_db_tmp["results"] = incidents_db_tmp["results"] + tmp_db["results"]
          field_next = tmp_db["next"]
        end
        if field_next != nil
          url = field_next
        else
          stop_load = false
        end
      rescue JSON::ParserError => e
        @logger.warn("JSON CMD ERROR PARSE:", :string => response.body)
      end
    end
    @incidents_db = incidents_db_tmp
    @logger.warn("INCIDENT DB LOADED")
  end
end # class LogStash::Outputs::Example
