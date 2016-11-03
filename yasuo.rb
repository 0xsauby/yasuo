#!/usr/bin/env ruby

## == Author
## Author::  Saurabh Harit [0xsauby]
## Copyright:: Copyright (c) 2014 Saurabh Harit
## License:: GPLv3
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

require "csv"
require "net/http"
require "net/http/persistent"
require "net/https"
require "nmap/program"
require "nmap/xml"
require "optparse"
require "ostruct"
require "text-table"
require "uri"
require "thread"
require 'yaml'
require 'logger'
require 'sqlite3'
require 'fileutils'

require File.dirname(File.realpath(__FILE__)) + '/formloginbrute.rb'

VERSION = '2.3'

class String
  def red; colorize(self, "\e[1m\e[31m"); end
  def green; colorize(self, "\e[1m\e[32m"); end
  def bold; colorize(self, "\e[1m"); end
  def colorize(text, color_code)  "#{color_code}#{text}\e[0m" end
end

class MultiDelegator
  def initialize(*targets)
    @targets = targets
  end

  def self.delegate(*methods)
    methods.each do |m|
      define_method(m) do |*args|
        @targets.map { |t| t.send(m, *args) }
      end
    end
    self
  end

  class <<self
    alias to new
  end
end

class Scanner
  def initialize(paths_filename, nmap_filename, target_file, savedURLs_filename, target_ips_range, scan_port_range, scan_all_ports, brute_force_mode, number_of_threads)
    #Logger
    FileUtils::mkdir_p 'logs'
    yasuolog = 'logs/yasuo_output_' + Time.now.strftime('%Y-%m-%d_%H-%M-%S') + '.log'
    $log_file = File.open(yasuolog, "a")
    $logboth = Logger.new MultiDelegator.delegate(:write, :close).to(STDOUT, $log_file)
    $logfile = Logger.new MultiDelegator.delegate(:write, :close).to($log_file)
    $logconsole = Logger.new MultiDelegator.delegate(:write, :close).to(STDOUT)
    @outdb = 'logs/yasuo_output_' + Time.now.strftime('%Y-%m-%d_%H-%M-%S') + '.db'

    # vulnerable applications signatures
    @paths_filename = paths_filename

    # nmap XML file
    @nmap_filename = nmap_filename
    
    # input file for hosts
    @target_file = target_file

    # File with exploitable URLs saved from last Yasuo run
    @savedURLs_filename = savedURLs_filename

    # the range of IPs to scan
    @target_ips_range = target_ips_range

    # scan the given range of ports
    @scan_port_range = scan_port_range

    # scan all ports
    @scan_all_ports = scan_all_ports

    # how should the scanner brute force applications that are found:
    #  - form (attempt to login to login forms found on pages)
    #  - basic (just use HTTP basic auth)
    #  - both
    @brute_force_mode = brute_force_mode.downcase

    # Number of threads to use with the scanner
    @thread_count = number_of_threads

    # stores discovered vulnerable applications
    @info = [
      ["App Name", "URL to Application", "Potential Exploit", "Username", "Password"]
    ]

    # stores discovered vulnerable applications
    begin
      @yasuodb = SQLite3::Database.new @outdb
      @yasuodb.execute "CREATE TABLE IF NOT EXISTS VulnApps(AppName STRING, AppURL STRING, Exploit STRING, Username STRING, Password STRING)"
    rescue SQLite3::Exception => e
      puts "Exception occurred"
      puts e
    end
  end

  def run
    # logic to determine if scan is performed
    if @nmap_filename.empty? and @savedURLs_filename.nil?
      $logboth.info("Initiating port scan")
      nmap_scan
    end

    if @savedURLs_filename.nil?
      # look through nmap scan output to find vulnerable applications
      process_nmap_scan
    else
      #Uses the saved good URLs in file from the initial Yasuo run rather than repeating the whole process
      process_savedgoodURLs_file
    end
  end

private

  # Runs an nmap scan, storing the result of the scan to the file system.
  # We currently do not clean up these files after our program has finished
  # running.
  def nmap_scan
    # silence sdtout for the duration of this method
    orig_std_out = $stdout.clone
    $stdout.reopen("/dev/null", "w")

    Nmap::Program.scan do |nmap|
      nmap.syn_scan = true
      nmap.service_scan = true
      nmap.xml = 'logs/nmap_output_' + Time.now.strftime('%Y-%m-%d_%H-%M-%S') + '.xml'
      nmap.os_fingerprint = false
      nmap.verbose = false

      if @target_file.length > 1
        nmap.target_file = @target_file
      else
        nmap.targets = @target_ips_range
      end

      # Logic for determining which ports are to be scanned by the script.
      # TODO: what happens if neither flag is provided? Should we default to
      #       all? (drop that flag.)
      nmap.ports = if @scan_all_ports
        "1-65535"
      elsif not @scan_port_range.empty?
        @scan_port_range
      end

      # Set the input filename so that when process_nmap_scan is called it will scan the
      # default scan output.
      # TODO: we don't clean up this file.
      @nmap_filename = "#{nmap.xml}"
    end
  ensure
    $stdout.reopen(orig_std_out)
  end

  def process_savedgoodURLs_file

    $logboth.info("<<<Reading all saved URLs from the provided file>>>")
    @target_urls = []
    File.read(@savedURLs_filename).each_line do |goodurl|
      @target_urls << goodurl.chop
    end
    p @target_urls

    slice_size = (@target_urls.size/Float(@thread_count)).ceil
    thread_list = @target_urls.each_slice(slice_size).to_a

    threads = []
    @thread_count.times do |i|
      if thread_list[i] != nil
        threads << Thread.new do
          if i == 0
            $logboth.info("<<<Enumerating vulnerable applications>>>")
          end
          find_vulnerable_applications(thread_list[i])
        end
      end
    end

    threads.each do |scan_thread| 
      scan_thread.join
    end

    $logfile.info("--------------------------------------------------------")
    $logfile.info("<<<Yasuo discovered following vulnerable applications>>>")
    $logfile.info("--------------------------------------------------------")
    $logfile.info("#{@info}")

    puts ""
    puts ""
    puts "--------------------------------------------------------"
    puts "<<<Yasuo discovered following vulnerable applications>>>".green
    puts "--------------------------------------------------------"
    puts @info.to_table(:first_row_is_head => true)
    @yasuodb.close
  end

  def process_nmap_scan

    urlstatefile = 'logs/savedURLstate_' + Time.now.strftime('%Y-%m-%d_%H-%M-%S') + '.out'
    $logboth.info("Using nmap scan output file #{@nmap_filename}")
    @target_urls = []
    @open_ports = 0

    xml = Nmap::XML.new(@nmap_filename)

    slice_size = (xml.hosts.size/Float(@thread_count)).ceil
    thread_list = xml.hosts.each_slice(slice_size).to_a

    threads = []
    @thread_count.times do |i|
      if thread_list[i] != nil
        threads << Thread.new do
          detect_targets(thread_list[i])
        end
      end
    end

    threads.each do |scan_thread|
      scan_thread.join
    end

    if @open_ports.zero?
      $logfile.warn("Either all the ports were closed or Yasuo did not find any web-based services.\n")
      $logfile.warn("Check #{@nmap_filename} for scan output\n")
    end

    if !@target_urls.empty?
      File.open(urlstatefile, "w+") do |goodurls|
        goodurls.puts(@target_urls)
      end
      slice_size = (@target_urls.size/Float(@thread_count)).ceil
      thread_list = @target_urls.each_slice(slice_size).to_a
    else
      $logboth.warn("Yasuo did not find any potential hosts to enumerate")
      exit
    end

   threads = []
   @thread_count.times do |i|
      if thread_list[i] != nil
        threads << Thread.new do
          if i == 0
            $logboth.info("<<<Enumerating vulnerable applications>>>")
          end
          find_vulnerable_applications(thread_list[i])
        end
      end
    end

    threads.each do |scan_thread| 
      scan_thread.join
    end

    #Shitty shitty logging
    $logfile.info("--------------------------------------------------------")
    $logfile.info("<<<Yasuo discovered following vulnerable applications>>>")
    $logfile.info("--------------------------------------------------------")
    $logfile.info("#{@info}")

    puts ""
    puts ""
    puts "--------------------------------------------------------"
    puts "<<<Yasuo discovered following vulnerable applications>>>".green
    puts "--------------------------------------------------------"
    puts @info.to_table(:first_row_is_head => true)
  end

  def detect_targets(hosts)
    fake_path = 'thisfilecanneverexistwtf.txt'
    fake_dir = 'thisfilecanneverexistwtf/'

    hosts.each do |host|
      $logfile.info("<<<Testing host - #{host.ip}>>>")
      #puts "\n<<<Testing host - #{host.ip}>>>".red

      host.each_port do |port|
        open_port = "#{port.state}" == "open"
	
	if "#{port.service}" != ''
          web_service = ("#{port.service}".include?("http") or "#{port.service}".include?("ssl") or "#{port.service}".include?("zeus") or "#{port.service}".include?("blackice") or port.service == "websm" or port.service.ssl?)
          wrapped_service = "#{port.service}".include?("tcpwrapped")
	end

        next unless open_port and (web_service or wrapped_service)
        @open_ports += 1

        if wrapped_service
          status = "tcpwrapped"
          schemes = ["https", "http"]
        else
          status = "open"
          if port.service.ssl? or "#{port.service}".include?("https") or "#{port.service}".include?("ssl")
            schemes = ["https"]
          else
            schemes = ["http"]
          end
        end

        schemes.each do |scheme|
          $logboth.info("Discovered #{status} port: #{host.ip}:#{port.number}")

          target_uri = "#{scheme}://#{host.ip}:#{port.number}"

          fake_uri     = "#{target_uri}/#{fake_path}"
          fake_dir_uri = "#{target_uri}/#{fake_dir}"

          use_ssl = (scheme == "https")
          fake_uri_resp = httpGETRequest(fake_uri, :use_ssl => use_ssl)
          fake_dir_resp = httpGETRequest(fake_dir_uri, :use_ssl => use_ssl)

          if (fake_uri_resp and fake_uri_resp.code != '200' and fake_uri_resp.code != '401' and fake_uri_resp.code != '403' and 
              fake_dir_resp and fake_dir_resp.code != '200' and fake_dir_resp.code != '401' and fake_dir_resp.code != '403')
            @target_urls.push(target_uri)
            break
          end

        end and $logfile.info("#{host.ip}:#{port.number} over #{schemes.join(' or ')} returns HTTP 200 or 401 for every requested resource. Ignoring it")
      end
    end
  end  

  def find_vulnerable_applications(target_urls)
    #Randomizing the array to distribute load. Go stealth or go home.
    target_urls = target_urls.shuffle

    # where we will store all the creds we find
    creds = []

    #Reading the signatures.yaml file
    @read_sigs = YAML.load_file(@paths_filename)

    @read_sigs.each_key { |appkey|
      default_path_1 = @read_sigs[appkey]['path1'].strip
      default_path_2 = @read_sigs[appkey]['path2'].strip
      version_string = @read_sigs[appkey]['vstring'].strip
      exploit_path = @read_sigs[appkey]['exppath'].strip
      default_creds = @read_sigs[appkey]['defcreds'].strip

      target_urls.each_with_index do |url, myindex|
        attack_url = url + default_path_1

        $logfile.info("Testing ----> [#{appkey}] #{attack_url}")
        #puts "Testing ----> [#{appkey}] #{attack_url}".red  #saurabh: comment this for less verbose output

        use_ssl = attack_url.include?  "https"
        resp = httpGETRequest(attack_url, :use_ssl => use_ssl)

        if ((resp != nil) and (resp.code != "200" and resp.code != "401" and resp.code != "403") and (default_path_2 != ''))
          $logfile.info("<<<Primary path {#{attack_url}} was not found, looking for secondary path>>>")
          #puts "<<<Primary path {#{attack_url}} was not found, looking for secondary path>>>".red
          attack_url = url + default_path_2
          $logfile.info("Testing ----> [#{appkey}] #{attack_url}")
          #puts "Testing ----> [#{appkey}] #{attack_url}".red
          resp = httpGETRequest(attack_url, :use_ssl => use_ssl)
        end

        if resp and resp.code == "301"
          if resp.header['location'].include? "http"
            resp = httpGETRequest(resp.header['location'], :use_ssl => use_ssl)
          else
            resp = httpGETRequest(attack_url + resp.header['location'], :use_ssl => use_ssl)
          end
        end

        if resp
          case resp.code
          when "200"
            target_urls.delete_at(myindex)

            if not resp.body.scan(/<form/i).empty? and not resp.body.scan(/login/i).empty?
              $logfile.info("[+] Yasuo found #{appkey} at #{attack_url}. May require form based auth")
              puts "[+] Yasuo found #{appkey} at #{attack_url}. May require form based auth".green
              if @brute_force_mode == 'form' or @brute_force_mode == 'all'
                $logboth.info("Double-checking if the application implements a login page and initiating login bruteforce, hold on tight...")
                creds = LoginFormBruteForcer::brute_by_force(attack_url,default_creds)
              else
                creds = ["N/A", "N/A"]
              end
            else
              $logfile.info("[+] Yasuo found an unauthenticated instance of #{appkey} at #{attack_url}.")
              puts "[+] Yasuo found an unauthenticated instance of #{appkey} at #{attack_url}.".green
              creds = ["None", "None"]
            end

            if not version_string.empty?
              $logboth.info("Checking if the detected application has the same version as specified in the signature file")
              if not resp.body.scan(/#{version_string}/i).empty?
                $logboth.info("Its a match. Version: #{version_string}.strip")
              else
                $logboth.info("The version string specified in the signature file did not match with the version of detected application.")
              end
            end

            @info.push([appkey, attack_url, exploit_path, creds[0], creds[1]])
            @yasuodb.execute("INSERT INTO VulnApps (AppName, AppURL, Exploit, Username, Password) VALUES(?, ?, ?, ?, ?)", appkey, attack_url, exploit_path, creds[0], creds[1])
            #break

          when "403"
            #This case may result in more false positives, but the behaviour was seen where you get a 403 and it takes you to a login.
            #
            target_urls.delete_at(myindex)
            
            if not resp.body.scan(/<form/i).empty? and not resp.body.scan(/login/i).empty?
              puts "[+] Yasuo found #{appkey} at #{attack_url}. Says not authorized but may contain login page".green
              if @brute_force_mode == 'form' or @brute_force_mode == 'all'
                $logboth.info("Double-checking if the application implements a login page and initiating login bruteforce attack, hold on tight...")
                creds = LoginFormBruteForcer::brute_by_force(attack_url,default_creds)
              else
                creds = ["N/A", "N/A"]
              end
            end
            if not version_string.empty?
              $logboth.info("Checking if the detected application has the same version as specified in the signature file")
              if not resp.body.scan(/#{version_string}/i).empty?
                $logboth.info("Its a match. Version: #{version_string}.strip")
              else
                $logboth.info("The version string specified in the signature file did not match with the version of detected application.")
              end
            end
            @info.push([appkey, attack_url, exploit_path, creds[0], creds[1]])
            @yasuodb.execute("INSERT INTO VulnApps (AppName, AppURL, Exploit, Username, Password) VALUES(?, ?, ?, ?, ?)", appkey, attack_url, exploit_path, creds[0], creds[1])
            #break
            
          when "401"
            target_urls.delete_at(myindex)

            $logfile.info("[+] Yasuo found #{appkey} at #{attack_url}. Requires HTTP basic auth")
            puts "[+] Yasuo found #{appkey} at #{attack_url}. Requires HTTP basic auth".green
            if @brute_force_mode == 'basic' or @brute_force_mode == 'all'
              $logboth.info("Initiating login bruteforce, hold on tight...")
              creds = brute_force_basic_auth(attack_url,default_creds)
            else
              creds = ["N/A", "N/A"]
            end
            if not version_string.empty?
              $logboth.info("Checking if the detected application has the same version as specified in the signature file")
              if not resp.body.scan(/#{version_string}/i).empty?
                $logboth.info("Its a match. Version: #{version_string}.strip")
              else
                $logboth.info("The version string specified in the signature file did not match with the version of detected application.")
              end
            end
            @info.push([appkey, attack_url, exploit_path, creds[0], creds[1]])
            @yasuodb.execute("INSERT INTO VulnApps (AppName, AppURL, Exploit, Username, Password) VALUES(?, ?, ?, ?, ?)", appkey, attack_url, exploit_path, creds[0], creds[1])
            #break

          when "404"
            next
          end
        end
      end
    }
  end

  # TODO: this is very similar to brute_by_force in formloginbrute.
  def brute_force_basic_auth(url401,dcreds)
    url = URI.parse(url401)

    #Smart brute-foce starts here
    puts ("[+] Trying app-specific default creds first -> #{dcreds}\n").green
    username = dcreds.split(':')[0].chomp
    password = dcreds.split(':')[1].chomp
    use_ssl = url.scheme == "https"
    response = httpGETRequest(url401, :username => username, :password => password, :use_ssl => use_ssl)

    sleep 0.5

    if response and (response.code == "200" or response.code == "301")
      $logfile.info("[+] Yatta, found default login credentials for #{url401} - #{username}:#{password}\n")
      puts ("[+] Yatta, found default login credentials for #{url401} - #{username}:#{password}\n").green
      return username, password
    end
    #Smart brute-foce ends here    

    LoginFormBruteForcer::usernames_and_passwords.each do |user, pass|
      username, password = user.chomp, pass.chomp
      use_ssl = url.scheme == "https"
      response = httpGETRequest(url401, :username => username, :password => password, :use_ssl => use_ssl)

      sleep 0.5

      if response and (response.code == "200" or response.code == "301")
        $logfile.info("[+] Yatta, found default login credentials for #{url401} - #{username}:#{password}\n")
        puts ("[+] Yatta, found default login credentials for #{url401} - #{username}:#{password}\n").green
        return username, password
      end
    end

    $logfile.info("Could not find default credentials, sucks")
    puts "Could not find default credentials, sucks".red
    return "Not Found", "Not Found"
  end

  def httpGETRequest(url, opts={})
    username = opts[:username] || ""
    password = opts[:password] || ""
    use_ssl  = opts[:use_ssl]  || false

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 5   #saurabh
    http.read_timeout = 5   #saurabh
    if use_ssl
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    request = Net::HTTP::Get.new(uri.request_uri)
    if not (username.empty? or password.empty?)
      request.basic_auth(username, password)
    end

    begin
      resp = http.request(request)
    rescue IOError, Errno::EINVAL, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError, Net::HTTP::Persistent::Error
      #exit
    rescue OpenSSL::SSL::SSLError
      $logfile.info("#{$url}: SSL Error, site might not use SSL")
    rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError, Errno::EHOSTUNREACH
      $logfile.info("#{$url}: Connection timed out or reset.")
    end

    return resp
  end
end

if __FILE__ == $0
  puts "#########################################################################################"
  puts "  oooooo   oooo       .o.        .oooooo..o ooooo     ooo   .oooooo.
   `888.   .8'       .888.      d8P'    `Y8 `888'     `8'  d8P'  `Y8b
    `888. .8'       .88888.     Y88bo.       888       8  888      888
     `888.8'       .8' `888.     `ZY8888o.   888       8  888      888
      `888'       .88ooo8888.        `0Y88b  888       8  888      888
       888       .8'     `888.  oo     .d8P  `88.    .8'  `88b    d88'
      o888o     o88o     o8888o 88888888P'     `YbodP'     `Y8bood8P'"
  puts "Welcome to Yasuo v#{VERSION}"
  puts "Author: Saurabh Harit (@0xsauby) | Contribution & Coolness: Stephen Hall (@logicalsec)"
  puts "#########################################################################################\n\n"

  options = OpenStruct.new
  options.nmap_file = ''
  options.ip_range = ''
  options.port_range = ''
  options.no_ping = false
  options.all_ports = false
  options.brute = ''
  options.thread_count = 1
  options.paths_file = ''
  options.target_file = ''
  #options.vomit = false

  OptionParser.new do |opts|
    opts.banner = "Yasuo #{VERSION}"

    opts.on("-s", "--path-signatures [FILE]", "YAML file containing signatures of vulnerable apps [Default - signatures.yaml]") do |file|
      options.paths_file = file
    end

    opts.on("-f", "--file [FILE]", "Nmap output in xml format") do |file|
      options.nmap_file = file
    end
    
    opts.on("-l", "--inputlist [FILE]", "New line delimited file of IP addresses you wish to scan") do |file|
      options.target_file = file
    end

    opts.on("-u", "--usesavedstate [FILE]", "Use saved good URLs from file") do |file|
      options.goodurls_file = file
    end

    opts.on("-r", "--range [RANGE]", "IP Range to Scan") do |iprange|
      options.ip_range = iprange
      if ("#{options.ip_range}".include? "file")
        ip_file = options.ip_range.split(':')[1].strip
        if (File.exists?(ip_file))
          #puts "user provided a file - #{ip_file}"
          ipaddrs = []
          ipaddrs = File.open(ip_file, "r").readlines.each {|line| line.strip!}
          options.ip_range = ipaddrs
          #puts "iprange is #{ipaddrs}"
        else
          puts "Please specify the correct filename and path"
          exit
        end
      end
    end

    opts.on("-n", "--noping", "Run the full TCP scan with no ping") do |noping|
      options.no_ping = true
    end

    opts.on("-p", "--port [PORT NUMBER]", "Ports to Scan") do |port_range|
      options.port_range = port_range
    end

    opts.on("-A", "--all_ports", "Scan on all 65535 ports") do |all_ports|
      options.all_ports = true
    end

    opts.on("-b", "--brute [all/form/basic]", "Bruteforce") do |brute|
      options.brute = brute
    end

    opts.on("-t", "--threads [Max Thread Count]", "Max number of threads to be used") do |thread_count|
      if thread_count.to_i > 0
        options.thread_count = thread_count.to_i
      else
        puts "Please enter a positive value for the number of threads"
        exit
      end
    end

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end

    opts.on("-v", "--version", "Get Version") do |ver|
      puts "Yasuo #{VERSION}"
      exit
    end

    #opts.on("--vomit", "Enable vomit mode to display all debug messages") do |vomit|
    #  options.vomit = true
    #end

  end.parse!(ARGV)

  unless options.nmap_file.length > 1 || options.target_file.length > 1  || options.ip_range.length > 1 || options.goodurls_file
    puts "To perform the Nmap scan, use the option -r to provide the network range or\n"
    puts "use the option -l to provide the list of IP hosts like nmap -iL.\n"
    puts "Additionally, also provide the port number(s) or choose either option -pA \n"
    puts "to scan all ports or option -pD to scan top 1000 ports.\n\n"
    puts "If you already have an Nmap scan output file in XML format, use -f\n"
    puts "to provide the file path and name\n\n"
    exit
  end

  unless options.paths_file.length > 1
    options.paths_file = 'signatures.yaml'
  end

  if not File.exists?(options.paths_file)
    puts "Yasuo needs a YAML file of path signatures to function.".red
    #$logboth.info('Yasuo needs a YAML file of path signatures to function.')
    exit
  end

  if not options.brute.empty? and (not File.exists?('users.txt') or not File.exists?('pass.txt'))
    puts "If you want to brute-force app authentication, ensure that you have both files users.txt and pass.txt".red
    exit
  end

  if not options.port_range.empty? and options.all_ports == true
    puts "Please only supply one port scanning option either -A or -p".red
    exit
  end

  #$spray = false
  #if options.vomit == true
  #  $spray = true
  #end

  # Let's go!
  Scanner.new(
    options.paths_file,
    options.nmap_file,
    options.target_file,
    options.goodurls_file,
    options.ip_range,
    options.port_range,
    options.all_ports,
    options.brute,
    options.thread_count
  ).run()
end
