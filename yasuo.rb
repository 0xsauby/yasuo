#!/usr/bin/env ruby

## == Author
## Author::  Saurabh Hariti [0xsauby]
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


require "colorize"
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

require File.dirname(File.realpath(__FILE__)) + '/resp200.rb'


VERSION = '0.1'


class Scanner
  def initialize(paths_filename, nmap_filename, target_ips_range, scan_port_range, scan_all_ports, brute_force_mode)
    # vulnerable applications signatures
    @paths_filename = paths_filename

    # nmap XML file
    @nmap_filename = nmap_filename

    # the range of IPs to scan
    @target_ips_range = target_ips_range

    # scan the given range of ports
    @scan_port_range = scan_port_range

    # scan all ports
    @input_port_all = scan_all_ports

    # how should the scanner brute force applications that are found:
    #  - form (attempt to login to login forms found on pages)
    #  - basic (just use HTTP basic auth)
    #  - both
    @brute_force_mode = brute_force_mode.downcase

    # stores vulnerable applications that were found
    @info = [
      ["URL to Application", "Potential Exploit", "Username", "Password"]
    ]
  end

  def run
    # logic to determine if scan is performed
    if @nmap_filename.empty?
      puts "Initiating port scan"
      puts "----------------------\n"
      nmap_scan
    end
    lameparse
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
      nmap.xml = 'nmap_output_' + Time.now.gmtime.to_s.gsub(/\W/,'') + '.xml'
      nmap.os_fingerprint = false
      nmap.verbose = false

      nmap.targets = @target_ips_range

      # Logic for determining which ports are to be scanned by the script.
      # TODO: what happens if neither flag is provided? Should we default to
      #       all? (drop that flag.)
      nmap.ports = if @scan_all_ports
        "1-65535"
      elsif not @scan_port_range.empty?
        @scan_port_range
      end

      # Set the input filename so that when lameparse is called it will scan the
      # default scan output.
      @nmap_filename = "#{nmap.xml}"
    end
  ensure
    $stdout.reopen(orig_std_out)
  end

  def lameparse
    fakepath = 'thisfilecanneverexistwtf.txt'
    fakedir = 'thisfilecanneverexistwtf/'

    final_urls = []

    puts "Using nmap scan output file #{@nmap_filename}"

    Nmap::XML.new(@nmap_filename) do |xml|
      xml.each_host do |host|
        puts "\n<<<Testing host - #{host.ip}>>>".red

        openportcount = 0
        host.each_port do |port|
          open_port = "#{port.state}" == "open"
          web_service = "#{port.service}".include?("http") or port.service == "websm" or "#{port.service}".include?("ssl")
          if open_port and web_service
            openportcount += 1

            port_number = "#{port.number}"
            port_service = "#{port.service}"

            puts "Discovered open port: #{host.ip}:#{port_number}"

            # Determine if the service is running SSL and begin to build appropriate URL
            use_ssl    = port_service.include?("https") or port_service.include?("ssl")
            prefix     = use_ssl ? "https" : "http"
            targeturi  = "#{prefix}://#{host.ip}:#{port_number}"
            fakeuri    = "#{targeturi}/#{fakepath}"
            fakediruri = "#{targeturi}/#{fakedir}"

            fake_uri_resp = httpGETRequest(fakeuri, :use_ssl => true)
            fake_dir_resp = httpGETRequest(fakediruri, :use_ssl => true)

            if (fake_uri_resp and fake_uri_resp.code != '200' and fake_uri_resp.code != '401' and
                fake_dir_resp and fake_dir_resp.code != '200' and fake_dir_resp.code != '401')
              final_urls << targeturi
            else
              puts "#{targeturi} returns HTTP 200 or 401 for every requested resource. Ignoring it"
            end
          end
        end

        if openportcount.zero?
          puts "Either all the ports were closed or Yasuo did not find any web-based services.\n".red
          puts "Check #{@nmap_filename} for scan output\n".red
        end
      end
    end

    lamerequest(final_urls)

    puts ""
    puts ""
    puts "--------------------------------------------------------"
    puts "<<<Yasuo discovered following vulnerable applications>>>".red
    puts "--------------------------------------------------------"
    puts @info.to_table(:first_row_is_head => true)
  end

  def lamerequest(thefinalurls)
    puts "\n<<<Randomizing target urls to avoid detection>>>".red
    thefinalurls = thefinalurls.shuffle   #Randomizing the array to distribute load. Go stealth or go home

    #Reading and processing the default path file
    defpath = ""
    resp = ""
    pathfile = @paths_filename
    creds = Array.new

    puts "\n<<<Enumerating vulnerable applications>>>".red
    puts "-------------------------------------------\n"

    CSV.foreach(pathfile) do |row|
      defpath = "#{row[0].strip}"
      script = row[1]
      thefinalurls.each_with_index do |url, myindex|
        attackurl = url + defpath
        puts "Testing ----> ".red + "#{attackurl}"  #saurabh: comment this for less verbose output
        if("#{attackurl}".include?  "https")
          resp = httpGETRequest(attackurl, :use_ssl => true)
          if ((resp != nil) and (resp.code == "301"))
            if ("#{resp.header['location']}".include? "http")
              resp = httpGETRequest(resp.header['location'], :use_ssl => true)
            else
              resp = httpGETRequest("#{attackurl}" + resp.header['location'], :use_ssl => true)
            end
          end
        else
          resp = httpGETRequest(attackurl)
          if ((resp != nil) and (resp.code == "301"))
            #location header may contain absolute or relative path; hence this check
            if ("#{resp.header['location']}".include? "http")
              resp = httpGETRequest(resp.header['location'])
            else
              resp = httpGETRequest("#{attackurl}" + resp.header['location'])
            end
          end
        end

        if (resp != nil)
          case resp.code
          when "200"
            thefinalurls.delete_at(myindex)
            if (((resp.body.scan(/<form/i)).size != 0) and ((resp.body.scan(/login/i)).size != 0))
              puts "Yasuo found - #{attackurl}. May require form based auth".green
              if @brute_force_mode == 'form' or @brute_force_mode == 'all'
                puts "Double-checking if the application implements a login page and initiating login bruteforce attack, hold on tight..."
                creds = LoginFormBruteForcer::brute_by_force(attackurl)
              else
                creds = ["N/A", "N/A"]
              end
            else
              puts "Yasuo found - #{attackurl}. No authentication required".green
              creds = ["None","None"]
            end
            @info.push([attackurl, script, creds[0], creds[1]])
            break
          when "401"
            thefinalurls.delete_at(myindex)
            puts "Yasuo found - #{attackurl}. Requires HTTP basic auth".green
            if ((@input_brute == 'basic') or (@input_brute == 'all'))
              puts "Initiating login bruteforce attack, hold on tight..."
              creds = lameauthbrute(attackurl)
            else
              creds = ["N/A", "N/A"]
            end
            @info.push([attackurl, script, creds[0], creds[1]])
            break
          when "404"
            next
          end
        end
      end
    end
  end

  # TODO: this is very similar to brute_by_force in resp200.
  def lameauthbrute(url401)
    url = URI.parse(url401)

    LoginFormBruteForcer::usernames_and_passwords.each do |user, pass|
      username, password = user.chomp, pass.chomp
      use_ssl = url.scheme == "https"
      response = httpGETRequest(url401, :username => username, :password => password, :use_ssl => use_ssl)

      sleep 0.5  # RAM: why?

      if response and (response.code == "200" or response.code == "301")
        puts ("Yatta, found default login credentials - #{username} / #{password}\n").green
        return username, password
      end
    end

    puts "Could not find default credentials, sucks".red
    return "Not Found", "Not Found"
  end

  def httpGETRequest(url, opts={})
    username = opts[:username] || ""
    password = opts[:password] || ""
    use_ssl  = opts[:use_ssl] || false

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 5   #saurabh
    http.read_timeout = 5   #saurabh
    if use_ssl
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    request = Net::HTTP::Get.new(uri.request_uri)
    if (username != "" and password != "")
      request.basic_auth username, password
    end

    begin
      resp = http.request(request)
    rescue IOError, Errno::EINVAL, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError, Net::HTTP::Persistent::Error
      #exit
    rescue OpenSSL::SSL::SSLError
      puts "#{$url}: SSL Error, site might not use SSL"
      #exit #Saurabh - This exit breaks execution of the script. Remaining port and hosts will not be tested. All other exit statements should be commented as well.
    rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError
      puts "#{$url}: Connection timed out or reset."
      #exit
    end

    return resp
  end
end


if __FILE__ == $0
  puts "#########################################################################################"
  puts "oooooo   oooo       .o.        .oooooo..o ooooo     ooo   .oooooo.
   `888.   .8'       .888.      d8P'    `Y8 `888'     `8'  d8P'  `Y8b
    `888. .8'       .88888.     Y88bo.       888       8  888      888
     `888.8'       .8' `888.     `ZY8888o.   888       8  888      888
      `888'       .88ooo8888.        `0Y88b  888       8  888      888
       888       .8'     `888.  oo     .d8P  `88.    .8'  `88b    d88'
      o888o     o88o     o8888o 88888888P'     `YbodP'     `Y8bood8P'"
  puts "Welcome to Yasuo v#{VERSION}"
  puts "Author: Saurabh Harit (@0xsauby) | Contribution & Coolness: Stephen Hall (@_stephen_h)"
  puts "#########################################################################################\n\n"

  options = OpenStruct.new
  options.nmap_file = ''
  options.ip_range = ''
  options.port_range = ''
  options.no_ping = false
  options.all_ports = false
  options.brute = ''
  options.paths_file = 'default-path.csv'  # TODO: add option to set this value

  OptionParser.new do |opts|
    opts.banner = "Yasuo #{VERSION}"

    opts.on("-s", "--path-signatures", "CSV file of vulnerable app signatures") do |file|
      options.paths_file = file
    end

    opts.on("-f", "--file [FILE]", "Nmap output in xml format") do |file|
      options.nmap_file = file
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

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end

    opts.on("-v", "--version", "Get Version") do |ver|
      puts "Yasuo #{VERSION}"
      exit
    end
  end.parse!(ARGV)

  unless options.nmap_file.length > 1 || options.ip_range.length > 1
    puts "To perform the Nmap scan, use the option -r to provide the network range.\n"
    puts "Additionally, also provide the port number(s) or choose either option -pA \n"
    puts "to scan all ports or option -pD to scan top 1000 ports.\n\n"
    puts "If you already have an Nmap scan output file in XML format, use -f\n"
    puts "to provide the file path and name\n\n"
    exit
  end

  if not File.exists?(options.paths_file)
    puts "Yasou needs a CSV file of path signatures to function.".red
    exit
  end


  if not options.brute.empty? and (not File.exists?('users.txt') or not File.exists?('pass.txt'))
    puts "If you want to do bruteforcing please ensure you have both files users.txt and pass.txt".red
    exit
  end

  # Let's go!
  Scanner.new(
    options.paths_file,
    options.nmap_file,
    options.ip_range,
    options.port_range,
    options.all_ports,
    options.brute
  ).run()
end
