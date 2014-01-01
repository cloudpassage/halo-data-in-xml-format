#!/usr/bin/env ruby

require 'rubygems'
require 'halo-api-lib'

$outputFile = nil

class TestArgs
  attr_accessor :base_url, :key_id, :key_secret, :cmd, :arg, :include_events
  attr_accessor :enable_sca, :enable_svm, :enable_user_access, :starting_date
  attr_accessor :needs_usage

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
    @include_events = false
    @needs_usage = true
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
        if (! verifyISO8601(@starting_date))
          $stderr.puts("Invalid date/time specification (#{@starting_date}), see ISO-8601")
          allOK = false
          @needs_usage = false
        elsif (! isInPastISO8601(@starting_date))
          $stderr.puts("(#{@starting_date}) does not represent a date/time in the past")
          allOK = false
          @needs_usage = false
        end
      elsif (arg.start_with?("output=") || arg.start_with?("--output="))
        filename = arg.split('=')[1]
        $outputFile = File.open(filename,'w')
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
      elsif (arg == "scan=sca-with-events") || (arg == "--scan=sca-with-events")
        @enable_sca = true
        @enable_svm = false
        @enable_user_access = false
        @include_events = true
        @cmd = "issues"
      elsif (arg == "-h") || (arg == "-?")
        @cmd = nil
      else
        $stderr.puts "Unrecognized argument: #{arg}"
        allOK = false
        @needs_usage = true
      end
    end
    if (@starting_date != nil) && (! @include_events)
      $stderr.puts "The --starting option is only allowed with --scan=sca-with-events"
      allOK = false
      @needs_usage = false
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
      $stderr.puts "Auth file #{filename} does not exist"
      return false
    end
    File.readlines(filename).each do |line|
      key, value = line.chomp.split("|")
      if ((key != nil) && (value != nil) && ((@key_id == nil) || (@key_secret == nil)))
        @key_id = key
        @key_secret = value
      end
    end
    if @verbose
      puts "AuthFile: id=#{@key_id} secret=#{@key_secret}"
    end
    if @key_id == nil && @key_secret == nil
      $stderr.puts "missing both key ID and secret in auth file"
      false
    elsif @key_id == nil
      $stderr.puts "missing key ID in auth file"
      false
    elsif @key_secret == nil
      $stderr.puts "missing key secret in auth file"
      false
    else
      true
    end
  end

  def usage()
    $stderr.puts "Usage: #{File.basename($0)} [auth-flag] [url-flag] [cmd-flag] [options]"
    $stderr.puts "  where auth-flag can be one of:"
    $stderr.puts "    --auth=<id>,<secret>\tUse provided credentials"
    $stderr.puts "  where url-flag can be one or more of:"
    $stderr.puts "    --url=<url>\t\t\tOverride the base URL to connect to"
    $stderr.puts "    --localca\t\t\tUse local SSL cert file (needed on Windows)"
    $stderr.puts "  where cmd-flag can be one of:"
    $stderr.puts "    --scan=svm\t\t\tDump the SVM issues in XML format"
    $stderr.puts "    --scan=sca\t\t\tDump the SCA issues in XML format"
    $stderr.puts "    --scan=sca-with-events\tDump the SCA issues (including scan events) in XML format"
    $stderr.puts "    --user-access\t\tShow which users can access which servers in XML"
    $stderr.puts "  where options can be one or more of:"
    $stderr.puts "    --starting=<date>\t\tStart fetching events from this ISO-8601 date/time"
    $stderr.puts "    --output=<file>\t\tWrite XML to named file"
  end

  def checkDateString(date_str)
    date_fields = date_str.split("-")
    return false if (date_fields.length != 3)
    return false if (date_fields[0].to_i < 1900) || (date_fields[0].to_i > 9999)
    return false if (date_fields[1].to_i < 1) || (date_fields[1].to_i > 12)
    return false if (date_fields[2].to_i < 1) || (date_fields[2].to_i > 31)
    return true
  end

  def checkTimeString(time_str)
    time_fields = time_str.split(":")
    return false if (time_fields.length < 2) || (time_fields.length > 3)
    return false if (time_fields[0].to_i < 0) || (time_fields[0].to_i > 23)
    return false if (time_fields[1].to_i < 0) || (time_fields[1].to_i > 59)
    if (time_fields.length == 3)
      seconds, tz = time_fields[2].split("+")
      if (tz != nil)
        return false if ((tz.to_i < 0) || (tz.to_i > 1159))
        return false if ((tz.to_i % 100) > 59)
      end
      seconds, tz = seconds.split("-")
      if (tz != nil)
        return false if ((tz.to_i < 0) || (tz.to_i > 1159))
        return false if ((tz.to_i % 100) > 59)
      end
      seconds = seconds.split("Z")[0]
      whole_seconds, partial = seconds.split(".")
      return false if (whole_seconds.to_i < 0) || (whole_seconds.to_i > 59)
      return false if (partial != nil) && ((partial.to_i < 0) || (partial.to_i > 1000000))
    end
    return true
  end

  def verifyISO8601(dt_str)
    if (dt_str == nil) || (dt_str.length < 10)
      return false
    end
    # use regex as first line of checking, then try to use Ruby parsing to check
    if (/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{4})?)?$/ =~ dt_str)
      begin
        date_str, time_str = dt_str.split("T")
        return false if (! checkDateString(date_str))
        return false if ((time_str != nil) && (! checkTimeString(time_str)))
        return true
      rescue ArgumentError => e
        puts "Exception: #{e}"
        return false
      end
    else
      return false
    end
  end

  def isInPastISO8601(dt_str)
    now = Time.now.utc.iso8601
    return dt_str < now
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

def writeOutput(s)
  if ($outputFile != nil)
    $outputFile.puts s
  else
    puts s
  end
end

def dumpServer(prefix,server,glist)
  writeOutput "#{prefix}<server>"
  writeOutput "#{prefix}  <hostname>#{server.hostname}</hostname>"
  writeOutput "#{prefix}  <id>#{server.id}</id>"
  writeOutput "#{prefix}  <connecting_ip_address>#{server.connecting_addr}</connecting_ip_address>"
  writeOutput "#{prefix}  #{findGroupForServer(server,glist)}"
  writeOutput "#{prefix}</server>"
end

def dumpSvm(server,svm,glist,eventMap,starting_date)
  if ((svm != nil) && (svm.findings != nil) && (! ((starting_date != nil) && (svm.created_at < starting_date))))
    svm.findings.each do |finding|
      writeOutput "  <finding>"
      writeOutput "    <id>#{server.id + '-' + finding.package_name}</id>"
      writeOutput "    <finding_type>svm</finding_type>"
      dumpServer("    ",server,glist)
      writeOutput "    <status>#{finding.status}</status>"
      writeOutput "    <package_name>#{finding.package_name}</package_name>"
      writeOutput "    <package_version>#{finding.package_version}</package_version>"
      writeOutput "    <critical>#{finding.critical}</critical>"
      writeOutput "    <created_at>#{svm.created_at}</created_at>"
      writeOutput "    <completed_at>#{svm.completed_at}</completed_at>"
      if (finding.cve_entries != nil)
        writeOutput "    <cve_entries>"
        finding.cve_entries.each do |cve|
          writeOutput "      <cve_entry>"
          writeOutput "        <cve_id>#{cve.cve_entry}</cve_id>"
          writeOutput "        <suppressed>#{cve.suppressed}</suppressed>"
          writeOutput "      </cve_entry>"
        end
        writeOutput "    </cve_entries>"
      else
        writeOutput "    <cve_entries/>"
      end
      writeOutput "  </finding>"
    end
  end
end

def dumpSca(server,sca,glist,eventMap,starting_date)
  if ((sca != nil) && (sca.findings != nil))
    sca.findings.each do |finding|
      writeOutput "  <finding>"
      writeOutput "    <id>#{server.id + '-' + finding.rule_name}</id>"
      writeOutput "    <finding_type>sca</finding_type>"
      dumpServer("    ",server,glist)
      writeOutput "    <rule_name>#{finding.rule_name}</rule_name>"
      writeOutput "    <critical>#{finding.critical}</critical>"
      writeOutput "    <status>#{finding.status}</status>"
      writeOutput "    <created_at>#{sca.created_at}</created_at>"
      writeOutput "    <completed_at>#{sca.completed_at}</completed_at>"
      if (finding.details != nil)
        finding.details.each do |detail|
          writeOutput "    <detail>"
          writeOutput "      " + dumpTag("type",detail.type)
          writeOutput "      " + dumpTag("target",detail.target)
          writeOutput "      " + dumpTag("actual",detail.actual)
          writeOutput "      " + dumpTag("expected",detail.expected)
          writeOutput "      " + dumpTag("status",detail.status)
          writeOutput "      " + dumpTag("scan_status",detail.scan_status)
          writeOutput "      " + dumpTag("config_key",detail.config_key)
          writeOutput "      " + dumpTag("config_key_value_delimiter",detail.config_key_value_delimiter)
          writeOutput "    </detail>"
        end
      end
      key = "#{server.id}\t#{finding.rule_name}"
      if (eventMap != nil) && (eventMap[key] != nil)
        evlist = eventMap[key]
        evlist.each do |event|
          writeOutput "    <event>"
          writeOutput "      " + dumpTag("name",event.name)
          writeOutput "      " + dumpTag("created_at",event.created_at)
          writeOutput "      " + dumpTag("object_name",event.object_name)
          writeOutput "      " + dumpTag("message",event.message) # might need to be escaped
          writeOutput "    </event>"
        end
      end
      writeOutput "  </finding>"
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
        # writeOutput "Event: #{event.to_s}"
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
    writeOutput "  <server>"
    writeOutput "    <hostname>#{server.hostname}</hostname>"
    writeOutput "    <id>#{server.id}</id>"
    writeOutput "    <platform>#{server.platform}</platform>"
    writeOutput "    <connecting_ip_address>#{server.connecting_addr}</connecting_ip_address>"
    group = groupsByServerId[server.id]
    if (group != nil)
      writeOutput "    <server_group>#{group.name}</server_group>"
    end
    fwpID = nil
    if (server.platform == 'windows')
      fwpID = group.windows_firewall_policy_id
    else # elsif (server.platform == 'linux')
      fwpID = group.linux_firewall_policy_id
    end
    # writeOutput "    <firewall-policy-id>#{fwpID}</firewall-policy-id>"
    if (fwpID != nil) && (usersById[fwpID] != nil)
      if (usersById[fwpID] == :All)
        # writeOutput "    <all-users>"
        writeOutput "    <users>"
        all_users.each { |user| writeOutput "      <user>#{user.username}</user>" }
        writeOutput "    </users>"
      elsif (usersById[fwpID] == [])
        writeOutput "    <users/>"
      else
        writeOutput "    <users>"
        usersById[fwpID].each { |username| writeOutput "      <user>#{username}</user>" }
        writeOutput "    </users>"
      end
    else
      writeOutput "    <users/>"
    end
    writeOutput "  </server>"
  end
end

cmd_line = TestArgs.new()
cmd_line.parse(ARGV)
if (cmd_line.cmd == nil)
  cmd_line.usage if cmd_line.needs_usage
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
  if (cmd_line.enable_sca && cmd_line.include_events) # eventually add svm and other scans which may reference events
    eventMap = getSortedEvents(client,cmd_line.starting_date)
  else
    eventMap = {}
  end

  if (cmd_line.enable_sca || cmd_line.enable_svm)
    writeOutput "<findings>"
    server_list.each do |server|
      issues = server.detailed_issues client
      if (cmd_line.enable_sca)
        dumpSca(server,issues.sca,groupsByServerId,eventMap,cmd_line.starting_date)
      end
      if (cmd_line.enable_svm)
        dumpSvm(server,issues.svm,groupsByServerId,eventMap,cmd_line.starting_date)
      end
    end
    writeOutput "</findings>"
  elsif (cmd_line.enable_user_access)
    writeOutput "<servers>"
    dumpUserAccess(client,server_list,group_list,groupsByServerId)
    writeOutput "</servers>"
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
ensure
  $outputFile.close() unless $outputFile == nil
end
