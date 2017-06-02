# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require 'erb'
require 'digest'
require 'openssl'

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::Enrsig < LogStash::Filters::Base
  config_name "enrsig"
  
  # File containt configuration
  #{'WHOIS': {'value_format': ['regexp_valid_value_for_$1$',...]", 'command_path': '/usr/local/cmd', 'command_syntax': "-x ... $1$ $2$"},'result_parse': 'template_create_json.erb'}
  #$1$ is first element in element content in query: [{WHOIS: {"id": id_rule, "field": [field_$1$], "name_in_db": "$1$"}},{SSL: {"id": id_rule, "field": [field_$1$,field_$2$], "name_in_db": "https://$1$:$2$"}}]
  config :conf_enrsig, :validate => :string, :default => "/etc/logstash/db/conf_enrsig.json"
  # delay to refresh configuration - default all hours
  config :refresh_interval_whois, :validate => :number, :default => 3600
  #field name where you add request for server add information active
  config :field_enr, :validate => :string, :default => "request_enrichiment"
  #enr_tag_response used for identify who is origin of resquest, and send response to good server
  config :enr_tag_response, :validate => :string, :required => :true, :default => "ENR_RETURN_TO_JOHN"

  public
  def register
    @logger.info("Configuration Loading...")
    @cmd_db = {}
    @conf_enr = {}
    @hash_conf = ""
    load_conf
    @logger.info("finish")
    @next_refresh = Time.now + @refresh_interval
    @load_statut = true
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    tnow = Time.now
    if @next_refresh < tnow
      if @load_statut == true
        @load_statut = false
        @logger.info("Configuration refresh...")
        load_conf
        @next_refresh = tnow + @refresh_interval
        @load_statut = true
      end
    end
    sleep(1) until @load_statut
    #verify if conf is not empty, if message contains ask
    if not @conf_enr.nil? and event.get(@field_enr).is_a?(Array)
      response=event.get(@field_enr).dup
      #verify if command exist in conf
      cnt_ea=0
      for request_cmd in event.get(@field_enr)
        if request_cmd.is_a?(Hash) and not request_cmd.empty?
          unless @conf_enr[request_cmd.keys[0]].is_a?(Hash)
            #verify if answer already present in db
            if not @cmd_db[request_cmd.keys[0]].is_a?(Hash) and @cmd_db[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['name_in_db']].is_a?(Hash)
              #add info
              response[cnt_ea][request_cmd.keys[0]]['response']=@cmd_db[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['name_in_db']]
            else
              #verify if field is present in event
              next if request_cmd[request_cmd.keys[0]]['value_format'].length != request_cmd[request_cmd.keys[0]]['field'].length
              syntax_cmd=@conf_enr[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['command_syntax']].dup
              #if field link not present, next!
              pnext=false
              cnt_e=1
              for flval in request_cmd[request_cmd.keys[0]]['field']
                if event.get(flval.to_s).nil?
                  pnext=true
                  break
                else
                  #create syntaxe
                  value_e=event.get(flval.to_s)
                  pvf=cnt_e-1
                  #verify format (avoid vulnerability escape) || FILTER
                  if value_e =~ /#{request_cmd[request_cmd.keys[0]]['value_format'][pvf]}/i
                    syntax_cmd.gsub! '$'+cnt_e.to_s+'$', value_e
                    cnt_e+=1
                  end
                end
              end
              next if pnext
              next if cnt_e != request_cmd[request_cmd.keys[0]]['field'].length or syntax_cmd =~ /\$\d+\$/
              #run cmd
              output_cmd = `#{@conf_enr[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['command_path']]} #{syntax_cmd}`
              #collect result and format
              result=JSON.parse(ERB.new(@conf_enr[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['command_syntax']]).result(binding))
              #insert in response
              response[cnt_ea][request_cmd.keys[0]]['response']=result
              #insert in db
              @cmd_db[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['name_in_db']] = {} if @cmd_db[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['name_in_db']].nil?
              @cmd_db[request_cmd.keys[0]][request_cmd[request_cmd.keys[0]]['name_in_db']]=result
            end
            #finish (resend to origin)
            event.set(@field_enr,response)
          end
        end
        cnt_ea+=1
      end
    end
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
  
  private
  def load_conf
    if !File.exists?(@conf_enrsig)
      @logger.warn("DB file read failure, stop loading", :path => @conf_enrsig)
      exit -1
    end
    tmp_hash = Digest::SHA256.hexdigest File.read @conf_enrsig
    if not tmp_hash == @hash_conf
      @hash_conf = tmp_hash
      begin
        tmp_enr = JSON.parse( IO.read(@conf_enrsig, encoding:'utf-8') )
        #create db structure
        @conf_enr = tmp_enr
        @conf_enr.each do |k,v|
          @cmd_db[k]={} if @cmd_db[k].nil?
        end
      rescue
        @logger.error("JSON CONF ENR_SIG -- PARSE ERROR")
      end
    end
  end
end # class LogStash::Filters::Example
