#!/usr/bin/env ruby

require 'rubygems'
require 'halo-api-lib'

class TestArgs
  attr_accessor :base_url, :key_id, :key_secret, :cmd, :arg
  attr_accessor :enable_sca, :enable_svm, :enable_user_access, :starting_date

  def initialize()
    @base_url = "https://portal.cloudpassage.com/"
    @key_id = nil
    @key_secret = nil
    @arg = nil
    @enable_sca = false
    @enable_svm = false
    @enable_user_access = false
    @cmd = nil
    @starting_date = nil
  end

  def parse(args)
    allOK = true
    args.each do |arg|
      if (arg.start_with?("auth=") || arg.start_with?("--auth="))
        authParam = arg.split('=')[1]
        if (File.file?(authParam) || (! authParam.include?(",")))
          if (! readAuthFile(authParam))
            @cmd = nil
            return
          end
        else
          @key_id, @key_secret = authParam.split(",")
        end
      elsif (arg.start_with?("url=") || arg.start_with?("--url="))
        @base_url = arg.split('=')[1]
      elsif (arg.start_with?("starting=") || arg.start_with?("--starting="))
        @starting_date = arg.split('=')[1]
      elsif (arg == "localca") || (arg == "--localca")
        ENV['SSL_CERT_FILE'] = File.expand_path(File.dirname(__FILE__)) + "/certs/cacert.pem"
      elsif (arg == "scan=sca") || (arg == "--scan=sca")
        @enable_sca = true
        @enable_svm = false
        @enable_user_access = false
        @cmd = "issues"
      elsif (arg == "scan=svm") || (arg == "--scan=svm")
        @enable_sca = false
        @enable_svm = true
        @enable_user_access = false
        @cmd = "issues"
      elsif (arg == "user-access") || (arg == "--user-access")
        @enable_sca = false
        @enable_svm = false
        @enable_user_access = true
        @cmd = "issues"
      elsif (arg == "-h") || (arg == "-?")
        @cmd = nil
      else
        puts "Unrecognized argument: #{arg}"
        allOK = false
      end
    end
    if ! allOK
      @cmd = nil
    end
    if (@key_id == nil) || (@key_secret == nil)
      if (! readAuthFile("issues.auth"))
        @cmd = nil
      end
    end
  end

  def readAuthFile(filename)
    if not File.exists? filename
      puts "Auth file #{filename} does not exist"
      return false
    end
    File.readlines(filename).each do |line|
      key, value = line.chomp.split("=")
      if key == "id"
        @key_id = value
      elsif key == "secret"
        @key_secret = value
      else
        puts "Unexpected key (#{key}) in auth file #{filename}"
      end
    end
    if @verbose
      puts "AuthFile: id=#{@key_id} secret=#{@key_secret}"
    end
    if @key_id == nil && @key_secret == nil
      puts "missing both key ID and secret in auth file"
      false
    elsif @key_id == nil
      puts "missing key ID in auth file"
      false
    elsif @key_secret == nil
      puts "missing key secret in auth file"
      false
    else
      true
    end
  end

  def usage()
    puts "Usage: #{File.basename($0)} [auth-flag] [url-flag] [cmd-flag] [options]"
    puts "  where auth-flag can be one of:"
    puts "    --auth=<id>,<secret>\tUse provided credentials"
    puts "  where url-flag can be one or more of:"
    puts "    --url=<url>\t\tOverride the base URL to connect to"
    puts "    --localca\t\tUse local SSL cert file (needed on Windows)"
    puts "  where cmd-flag can be one of:"
    puts "    --scan=svm\t\tDump the SVM issues in XML format"
    puts "    --scan=sca\t\tDump the SCA issues in XML format"
    puts "    --user-access\tShow which users can access which servers in XML"
    puts "  where options can be one or more of:"
    puts "    --starting=<date>\tStart fetching events from ISO-8601 date/time"
  end
end

def dumpTag(tagName,value)
  if ((value != nil) && (value.to_s.length > 0))
    s = "<#{tagName}>#{value}</#{tagName}>"
  else
    s = "<#{tagName}/>"
  end
  s
end

def dumpServer(prefix,server,glist)
  puts "#{prefix}<server>"
  puts "#{prefix}  <hostname>#{server.hostname}</hostname>"
  puts "#{prefix}  <id>#{server.id}</id>"
  puts "#{prefix}  <connecting_ip_address>#{server.connecting_addr}</connecting_ip_address>"
  puts "#{prefix}  #{findGroupForServer(server,glist)}"
  puts "#{prefix}</server>"
end

def dumpSvm(server,svm,glist,eventMap)
  if ((svm != nil) && (svm.findings != nil))
    svm.findings.each do |finding|
      puts "  <finding>"
      puts "    <id>#{server.id + '-' + finding.package_name}</id>"
      puts "    <finding_type>svm</finding_type>"
      dumpServer("    ",server,glist)
      puts "    <status>#{finding.status}</status>"
      puts "    <package_name>#{finding.package_name}</package_name>"
      puts "    <package_version>#{finding.package_version}</package_version>"
      puts "    <critical>#{finding.critical}</critical>"
      if (finding.cve_entries != nil)
        puts "    <cve_entries>"
        finding.cve_entries.each do |cve|
          puts "      <cve_entry>"
          puts "        <cve_id>#{cve.cve_entry}</cve_id>"
          puts "        <suppressed>#{cve.suppressed}</suppressed>"
          puts "      </cve_entry>"
        end
        puts "    </cve_entries>"
      else
        puts "    <cve_entries/>"
      end
      puts "  </finding>"
    end
  end
end

def dumpSca(server,sca,glist,eventMap)
  if ((sca != nil) && (sca.findings != nil))
    sca.findings.each do |finding|
      puts "  <finding>"
      puts "    <id>#{server.id + '-' + finding.rule_name}</id>"
      puts "    <finding_type>sca</finding_type>"
      dumpServer("    ",server,glist)
      puts "    <rule_name>#{finding.rule_name}</rule_name>"
      puts "    <critical>#{finding.critical}</critical>"
      puts "    <status>#{finding.status}</status>"
      if (finding.details != nil)
        finding.details.each do |detail|
          puts "    <detail>"
          puts "      " + dumpTag("type",detail.type)
          puts "      " + dumpTag("target",detail.target)
          puts "      " + dumpTag("actual",detail.actual)
          puts "      " + dumpTag("expected",detail.expected)
          puts "      " + dumpTag("status",detail.status)
          puts "      " + dumpTag("scan_status",detail.scan_status)
          puts "      " + dumpTag("config_key",detail.config_key)
          puts "      " + dumpTag("config_key_value_delimiter",detail.config_key_value_delimiter)
          puts "    </detail>"
        end
      end
      key = "#{server.id}\t#{finding.rule_name}"
      if (eventMap != nil) && (eventMap[key] != nil)
        evlist = eventMap[key]
        evlist.each do |event|
          puts "    <event>"
          puts "      " + dumpTag("name",event.name)
          puts "      " + dumpTag("created_at",event.created_at)
          puts "      " + dumpTag("object_name",event.object_name)
          puts "      " + dumpTag("message",event.message) # might need to be escaped
          puts "    </event>"
        end
      end
      puts "  </finding>"
    end
  end
end

def sortEvents(evlist,evmap)
  if (evlist != nil) && (evmap != nil)
    evlist.each do |event|
      key = event.server_id
      if (key != nil)
        if (event.policy_name != nil)
          key += "\t#{event.policy_name}"
        elsif (event.rule_name != nil)
          key += "\t#{event.rule_name}"
        else
          key = nil
        end
      end
      if (key != nil)
        evmap[key] = [] if (evmap[key] == nil)
        evmap[key] << event
        # puts "Event: #{event.to_s}"
      end
    end
  end
end

def getSortedEvents(client,starting_date)
  evMap = {}
  batchCount = 1
  $stderr.puts "Retrieving first batch of events."
  resp = Halo::Events.all_first(client,100,starting_date)
  sortEvents(resp['evlist'],evMap) if (resp['evlist'] != nil)
  while (resp['next'] != nil)
    begin
      $stderr.puts "Retrieving batch #{batchCount} of events."
      resp = Halo::Events.all_next(client,resp['next'])
      sortEvents(resp['evlist'],evMap) if (resp['evlist'] != nil)
      batchCount += 1
    rescue Halo::AuthException => api_err
      $stderr.puts "Authentication timed-out, re-authenticating"
      token = client.token
    end
  end
  evMap
end

def findGroupForServer(server,glist)
  group = glist[server.id]
  if (group != nil)
    return "<server_group>#{group.name}</server_group>"
  end
  return "<server_group/>" # no match found
end

def dumpUserAccess(client,server_list,group_list,groupsByServerId)
  policy_list = Halo::FirewallPolicies.all client
  usersById = {}
  policiesById = {}
  policy_list.each do |policy|
    policiesById[policy.id] = policy
    userList = []
    rule_list = policy.rules client
    rule_list.each do |rule|
      if (userList != :All) && (rule.source != nil)
        srcObj = rule.source
        if (srcObj['type'] == "UserGroup")
          userList = :All
        elsif (srcObj['type'] == "User")
          userList << srcObj['username']
        end
      end
    end
    usersById[policy.id] = userList
  end

  all_users = Halo::Users.all client

  server_list.each do |server|
    puts "  <server>"
    puts "    <hostname>#{server.hostname}</hostname>"
    puts "    <id>#{server.id}</id>"
    puts "    <platform>#{server.platform}</platform>"
    puts "    <connecting_ip_address>#{server.connecting_addr}</connecting_ip_address>"
    group = groupsByServerId[server.id]
    if (group != nil)
      puts "    <server_group>#{group.name}</server_group>"
    end
    fwpID = nil
    if (server.platform == 'windows')
      fwpID = group.windows_firewall_policy_id
    else # elsif (server.platform == 'linux')
      fwpID = group.linux_firewall_policy_id
    end
    # puts "    <firewall-policy-id>#{fwpID}</firewall-policy-id>"
    if (fwpID != nil) && (usersById[fwpID] != nil)
      if (usersById[fwpID] == :All)
        # puts "    <all-users>"
        puts "    <users>"
        all_users.each { |user| puts "      <user>#{user.username}</user>" }
        puts "    </users>"
      elsif (usersById[fwpID] == [])
        puts "    <users/>"
      else
        puts "    <users>"
        usersById[fwpID].each { |username| puts "      <user>#{username}</user>" }
        puts "    </users>"
      end
    else
      puts "    <users/>"
    end
    puts "  </server>"
  end
end

cmd_line = TestArgs.new()
cmd_line.parse(ARGV)
if (cmd_line.cmd == nil)
  cmd_line.usage
  exit
end

client = Halo::Client.new
client.base_url = cmd_line.base_url
client.key_id = cmd_line.key_id
client.key_secret = cmd_line.key_secret

begin
  # must call this as it forces retrieval of auth token
  token = client.token
rescue Halo::ConnectionException => conn_err
  $stderr.puts "Connection Error: " + conn_err.error_descr
  exit
rescue Halo::AuthException => api_err
  $stderr.puts "Auth Error: status=#{api_err.http_status} msg=" + api_err.error_msg
  $stderr.puts "            description=" + api_err.error_description
  $stderr.puts "            body=" + api_err.error_body
  exit  
rescue Halo::FailedException => api_err
  $stderr.puts "API Error: status=#{api_err.http_status} msg=" + api_err.error_msg
  $stderr.puts "           description=" + api_err.error_description
  $stderr.puts "           body=" + api_err.error_body
  exit  
end

begin
  server_list = Halo::Servers.all client
  # $stderr.puts "retrieved #{server_list.length} servers"

  groupsByServerId = {}
  group_list = Halo::ServerGroups.all client
  group_list.each do |group|
    slist = group.servers client
    slist.each { |server| groupsByServerId[server.id] = group }
  end

  # get events so we can add them to each issue's records
  if (cmd_line.enable_sca) # eventually add svm and other scans which may reference events
    eventMap = getSortedEvents(client,cmd_line.starting_date)
  else
    eventMap = {}
  end

  if (cmd_line.enable_sca || cmd_line.enable_svm)
    puts "<findings>"
    server_list.each do |server|
      issues = server.issues client
      if (cmd_line.enable_sca)
        dumpSca(server,issues.sca,groupsByServerId,eventMap)
      end
      if (cmd_line.enable_svm)
        dumpSvm(server,issues.svm,groupsByServerId,eventMap)
      end
    end
    puts "</findings>"
  elsif (cmd_line.enable_user_access)
    puts "<servers>"
    dumpUserAccess(client,server_list,group_list,groupsByServerId)
    puts "</servers>"
  end
rescue Halo::ConnectionException => conn_err
  $stderr.puts "Connection Error: " + conn_err.error_descr
  exit
rescue Halo::AuthException => api_err
  $stderr.puts "Auth Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  $stderr.puts "            description=#{api_err.error_description}"
  $stderr.puts "            body=#{api_err.error_body}"
  exit  
rescue Halo::FailedException => api_err
  $stderr.puts "API Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  $stderr.puts "           description=#{api_err.error_description}"
  $stderr.puts "           request_url=#{api_err.url}"
  $stderr.puts "           body=#{api_err.error_body}"
  exit  
end
