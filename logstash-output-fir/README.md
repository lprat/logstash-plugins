# Logstash Plugin

Logstash plugin output for send alert to FIR (Incident platform of Cert SG - https://github.com/certsocietegenerale/FIR)
** require manticore **

Work on version 5.x and older.

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Install
```
env GEM_HOME=/usr/share/logstash/vendor/bundle/jruby/1.9 /usr/share/logstash/vendor/jby/bin/jruby /usr/share/logstash/vendor/jruby/bin/gem build logstash-output-fir.gemspec
usr/share/logstash/bin/logstash-plugin install logstash-output-fir-2.0.0.gem
```

## Main Configuration (logstash-output.conf)
** Refresh DB : The plugin use some files configurations, you can change it during run. The plugin get change and apply all refresh time. You can use config/db file with git system... ** 
When i create alert/event in FIR, it's possible to update whith news informations (news alert in relationship, ...), the plugin can update a event FIR for avoid remake near event...
* url_api_fir [string]: The uri for send alert to FIR API (REST)
  * Example: "https://127.0.0.1:8000/api/"
* refresh_interval_remote [numeric]: Delay to refresh database by donwload incidentsDB in FIR (for re-syncronisation, when new event, is add in db_incident of logstash -- utility when you close event in FIR)
  * Example: 3600
  * If you have much incidents in DB, you take a long time for download DB...
* refresh_interval [numeric]: Delay to refresh configuration FIR
  * Example: 3600
* headers [hash]: You give token API FIR
  * Example: {"Authorization" => "Token 0000000000000000000000000000", "Content-Type" => "application/json"}
* ssl_options [string]: If you change SSL configuration of manticore, by example disable verify cert.
  * Example for disable verify: "{ :verify => :disable }"
* template_new [path]: the path of erb file for make body/description of event in FIR when new alert
  * Example "/etc/logstash/db/template_update.erb" (template example in folder: template_erb)
* template_update [path]: the path of erb file for make body/description of event in FIR when update alert
  * Example "/etc/logstash/db/template_new.erb" (template example in folder: template_erb)
* subj_template_new [path]: the path of erb file for make subject of event in FIR when new alert
  * Example "/etc/logstash/db/template_update.erb" (template example in folder: template_erb)
* subj_template_update [path]: the path of erb file for make subject of event in FIR when update alert
  * Example "/etc/logstash/db/template_new.erb" (template example in folder: template_erb)
* confile [path]: configuration file for rules of create event in FIR (filter and filter near event)
  * Example "/etc/logstash/db/conf_fir.json" (example in folder sample_conf)
* subject_field [string]: The name of field "subject" in event FIR when you create event
  * Example field by default: "subject"
* body_field [string]: The name of field "description" in event FIR when you create event 
  * Example field by default: "description"
* severity_field [string]: The name of field "severity" in event FIR when you create event
  * Example field by default: "severity"
* status_field [string]: The name of field "status" in event FIR when you create event
  * Example field by default: "status"
  
### conf_fir.json
The file contains rules which give filter and filter near event, choice template for create event in FIR
** This file is a Json format **
```
{ "rules": [
  {
   "filters": {"sig_detected_note": "3|4"},
    "subject_filter": "src_ip",
    "subject_filter_prefix": "-",
    "subject_filter_sufix": "-", 
    "body_filter": "fingerprint",
    "body_filter_prefix": "",
    "body_filter_sufix": " -> SCORE",
    "count_filter": " Count: ",
    "severity_add": "sig_detected_note", 
    "fields_create": {"actor": 6, "category": 26,"confidentiality": 0,"detection": 36, "plan": 37,"is_starred": false,"is_major": false,"is_incident": false,"concerned_business_lines": []},
    "template_new_sujet": "", 
    "template_new_body": "", 
    "template_up_sujet": "",
    "template_up_body": "",
  }
] }
```
Json contains key "rules" which contains all rule in hash format.
Each element of rule:
* filters [hash]: filter rule by field value, you can use multi field filter => {"field1": "regexp", "field2": "regexp"}
  * field_name [string]: name of field in event where you search regexp value
  * value_search [regexp]: regexp value to search in event field selected
* subject_filter [string]: When you match filter then you search if event is near. For apply, you search value of field event in subject of all incident FIR DB. If you find then event DB know server or client then you verify if same event for this client. Else you don't find value field event in incident DB, you create new event in FIR. The search use "subject == '*value_field_event*' "
* subject_filter_prefix [string]: For avoid error when match subject_filter you can add prefix and change search by "subject == '*prefix+value_field_event*' "
* subject_filter_sufix [string]: For avoid error when match subject_filter you can add sufix and change search by "subject == '*value_field_event+sufix*' "
* body_filter [string]: When subject matched, then verify if description event contains same event. I use fingerprint field (Plugin logstash-filter-sig) for it. If it find then stop, is ok, else, update event FIR with new event for client/server subject. The search use "body == '*value_field_event*' " (body is field description in FIR)
* body_filter_prefix [string]: For avoid error when match body_filter you can add prefix and change search by "body == '*prefix+value_field_event*' "
* body_filter_sufix [string]: For avoid error when match body_filter you can add sufix and change search by "body == '*value_field_event+sufix*' "
* count_filter [string]: For incriment count of number same alert receveive.
* severity_add [string]: The name of field used for copy value in severity field of FIR event. If empty then set severity to 1
* fields_create [hash]: contains information must need for create event in FIR
  * actor [numeric]: 1
  * category [numeric]: 2
  * confidentiality [numeric]: 1
  * detection [numeric]: 3
  * plan [numeric]: 4
  * is_starred [boolean]: false
  * is_major [boolean]: false
  * is_incident [boolean]: false
  * concerned_business_lines [array]: []
* template_new_sujet [path]: The path of file erb template for new subject
* template_new_body [path]: The path of file erb template for new description/body
* template_up_sujet [path]: The path of file erb template for update subject
* template_up_body [path]: The path of file erb template for update description/body

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
