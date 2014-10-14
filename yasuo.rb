#!/usr/bin/env ruby
#
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

require 'nmap/program'
require 'nmap/xml'
require "net/http"
require 'net/http/persistent' #install gem
require "net/https"
require "uri"
require 'csv'
require 'colorize'  #install gem
require './resp200.rb'

#puts("Usage: ruby testscan.rb IP_Address Port_Number\n
#IP_Address could be a single IP, a range of IPs or CIDR notation
#PORT_Number could be a single port, multiple comma separated ports, range of ports, all (for 1-65535 ports), leave blank to scan the top 1000 ports
puts "#########################################################################################"
puts "oooooo   oooo       .o.        .oooooo..o ooooo     ooo   .oooooo.
 `888.   .8'       .888.      d8P'    `Y8 `888'     `8'  d8P'  `Y8b
  `888. .8'       .88888.     Y88bo.       888       8  888      888
   `888.8'       .8' `888.     `ZY8888o.   888       8  888      888
    `888'       .88ooo8888.        `0Y88b  888       8  888      888
     888       .8'     `888.  oo     .d8P  `88.    .8'  `88b    d88'
    o888o     o88o     o8888o 88888888P'     `YbodP'     `Y8bood8P'"
puts "Welcome to Yasuo v0.1"
puts "Author: Saurabh Harit (@0xsauby) | Contribution & Coolness: Stephen Hall (@_stephen_h)"
puts "#########################################################################################\n\n"

#$fileout = $stdout.clone
#$stdout.reopen('yasuo_output.txt')

class Scan_and_parse

  VERSION = '0.1'

  def initialize(input_filename, input_iprange, input_portrange, input_portdefault, input_portall, input_brute)
    begin
      require 'nmap/program'
    rescue LoadError
      puts 'could not load the ruby-nmap library'
      puts 'Try gem install ruby-nmap'
      exit
    end

    if (File.exists?('default-path.csv') == false)
      puts "Yasou needs the default-path.csv file to run".red
      exit
    end
    if(input_brute != "")
      if ((File.exists?('users.txt') == false) or (File.exists?('pass.txt') == false))
        puts "If you want to do bruteforcing please ensure you have both files users.txt and pass.txt".red
        exit
      end
    end

    @input_filename = input_filename
    @input_iprange = input_iprange
    @input_portrange = input_portrange
    @input_portdefault = input_portdefault
    @input_portall = input_portall
    @input_brute = input_brute.downcase
    @info = Array.new

  end

  def lamescan
    orig_std_out = $stdout.clone
    $stdout.reopen("/dev/null", "w")
    Nmap::Program.scan do |nmap|
      nmap.syn_scan = true
      nmap.service_scan = false
      nmap.xml = 'nmap_output_' + Time.now.gmtime.to_s.gsub(/\W/,'') + '.xml'
      nmap.os_fingerprint = false
      nmap.verbose = false

      #Logic for determining which ports are to be scanned by the script
      if @input_portall == true
        nmap.ports = "1-65535"
      elsif @input_portrange != ''
        nmap.ports = @input_portrange
      elsif @input_portdefault == true
        nmap.top_ports = 1000
      end

      nmap.targets = @input_iprange
      #Set the input filename so that when lameparse is called it will scan the default scan output.
      @input_filename = "#{nmap.xml}"
    end
    $stdout.reopen(orig_std_out)
  end

  def lameparse
    fakepath = 'thisfilecanneverexistwtf.txt'
    if (File.exists?(@input_filename))
      puts "Using nmap scan output file #{@input_filename}"
      Nmap::XML.new(@input_filename) do |xml|
        xml.each_host do |host|
          openportcount = 0
          $vulnappfound = 0
          puts "[Testing host - #{host.ip}]".red
          $thisip = "#{host.ip}"
          host.each_port do |port|
            if((("#{port.service}".include? "http") || ("#{port.service}" == "websm") || ("#{port.service}".include? "ssl")) && ("#{port.state}" == "open"))
              openportcount += 1
              $portnum = "#{port.number}"
              $portproto = "#{port.protocol}"
              $portst = "#{port.state}"
              $portserv = "#{port.service}"
              puts "Discovered open port: #{$thisip}:#{$portnum}"
              puts "--------------------------------------------"
              #Determine if the service is running SSL and begin to build appropriate URL
              if(("#{$portserv}".include?  "https") || ("#{$portserv}".include?  "ssl"))
                $ssl = true
                $targeturi = "https://#{$thisip}:#{$portnum}"
                $fakeuri = "https://#{$thisip}:#{$portnum}/#{fakepath}"
                fakeresp = httpsGETRequest($fakeuri)
                #next
                if ((fakeresp != nil) and (fakeresp.code != '200') and (fakeresp.code != '401'))
                  lamerequest
                else
                  puts "#{$targeturi} returns HTTP 200 or 401 for every requested resource. Ignoring it"
                end
              else
                $ssl = false
                $targeturi = "http://#{$thisip}:#{$portnum}"
                $fakeuri = "http://#{$thisip}:#{$portnum}/#{fakepath}"
                fakeresp = httpGETRequest($fakeuri)
                #fakeresp will be null in case of an exception
                if ((fakeresp != nil) and (fakeresp.code != '200') and (fakeresp.code != '401'))
                  lamerequest
                  if ($vulnappfound == false)
                    puts "Yasuo did not find any vulnerable application on #{$thisip}:#{$portnum}\n\n"
                  end
                else
                  puts "#{$targeturi} returns HTTP 200 or 401 for every requested resource. Ignoring it"
                end
              end
            end
          end
          if openportcount == 0
            puts "Either all the ports were closed or Yasuo did not find any web-based services. Check #{@input_filename} for scan output\n".red
          end
        end
      end
    else
      puts "Please specify the correct filename and path\n\n"
    end

    puts ""
    puts ""
    puts "--------------------------------------------"
    puts "List of all applications found"
    puts "--------------------------------------------"
    @info.each do |host|
      puts ("#{host}").green
    end
  end

  def lamerequest
    #puts "Discovered open port: #{$thisip}:#{$portnum}"
    #puts "--------------------------------------------"

    #Reading and processing the default path file
    defpath = ""
    resp = ""
    pathfile = 'default-path.csv'
    creds = Array.new
    $vulnappfound = false

    puts "Enumerating vulnerable applications"
    puts "-------------------------------------\n"

    CSV.foreach(pathfile) do |row|
      defpath = "#{row[0].strip}"   #changing row[1] to row[0] based on the new defalt-path file format
      script = row[1]
      $finaluri = "#{$targeturi}#{defpath}"
      #puts "Testing ----> #{$finaluri}"
      #If the service is running SSL set the use_ssl variable to true.
      if($ssl == true)
        resp = httpsGETRequest($finaluri)
        if ((resp != nil) and (resp.code == "301"))
          if ("#{resp.header['location']}".include? "http")
            resp = httpsGETRequest(resp.header['location'])
          else
            resp = httpsGETRequest("#{$targeturi}" + resp.header['location'])
          end
        end
      else
        resp = httpGETRequest($finaluri)
        if ((resp != nil) and (resp.code == "301"))
          #location header may contain absolute or relative path; hence this check
          if ("#{resp.header['location']}".include? "http")
            resp = httpGETRequest(resp.header['location'])
          else
            resp = httpGETRequest("#{$targeturi}" + resp.header['location'])
          end
        end
      end

      if (resp != nil)
        #puts "Testing ----> #{$finaluri}"  #saurabh: comment this for less verbose output
        case resp.code
        when "200"
          if (((resp.body.scan(/<form/i)).size != 0) and ((resp.body.scan(/login/i)).size != 0))
            puts "Yasuo found - #{$finaluri}. May require form based auth".green
            if ((@input_brute == 'form') or (@input_brute == 'all'))
              puts "Double-checking if the application implements a login page and initiating login bruteforce attack, hold on tight..."
              creds = LoginFormBruteForcer::burtebyforce($finaluri)
            end
          else
            puts "Yasuo found - #{$finaluri}. No authentication required".green
            creds = ["None","None"]
          end
          $vulnappfound = true
          @info.push([$finaluri, script, creds[0], creds[1]])
          break
        when "401"
          puts "Yasuo found - #{$finaluri}. Requires HTTP basic auth".green
          if ((@input_brute == 'basic') or (@input_brute == 'all'))
            puts "Initiating login bruteforce attack, hold on tight..."
            creds = lameauthbrute($finaluri)
          end
          #puts creds
          $vulnappfound = true
          @info.push([$finaluri, script, creds[0], creds[1]])
          break
        when "404"
          #puts "Not found"
          next
        end
      end
    end
  end

  def lameauthbrute(url401)
    url = URI.parse(url401)
    win = 0
    user_found = "Not Found"
    pass_found = "Not Found"

    HttpFormBruteForcer::usernames_and_passwords.each do |user, pass|
      if (url.scheme == "https")
        res = httpsGETRequest(url401, user.chomp, pass.chomp)
        sleep 0.5
      else
        res = httpGETRequest(url401, user.chomp, pass.chomp)
        sleep 0.5
      end
      if ((res != nil) and (res.code == "200" or res.code == "301"))
        puts ("Yatta, found default login credentials - #{user.chomp} / #{pass.chomp}\n").green
        win = 1
        user_found = user.chomp
        pass_found = pass.chomp
      end
    end
    if win == 0
      puts("Could not find default credentials, sucks".red)
    end
    return user_found,pass_found
  end

  def httpsGETRequest(url, username="", password="")
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 5   #saurabh
    http.read_timeout = 5   #saurabh
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
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

  def httpGETRequest(url, username="", password="")
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 5   #saurabh
    http.read_timeout = 5   #saurabh
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
      #exit
    rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError
      puts "#{$url}: Connection timed out or reset."
      #exit
    end

    return resp
  end
end

if __FILE__ == $0
  require 'optparse'
  require 'ostruct'

  options = OpenStruct.new
  options.input_file = ''
  options.ip_range = ''
  options.port_range = ''
  options.no_ping = false
  options.default_ports_top = false
  options.all_ports_all = false
  options.brute = ''


  OptionParser.new do |opts|
    opts.banner = "Yasuo #{Scan_and_parse::VERSION}"

    opts.on("-f", "--file [FILE]", "Nmap output in xml format") do |file|
      options.input_file = file
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

    opts.on("-D", "--default_ports", "Scan on Nmap top 1000 ports") do |default_ports|
      options.default_ports_top = true
    end

    opts.on("-A", "--all_ports", "Scan on all 65535 ports") do |all_ports|
      options.all_ports_all = true
    end

    opts.on("-b", "--brute [all/form/basic]", "Bruteforce") do |brute|
      options.brute = brute
    end

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end

    opts.on("-v", "--version", "Get Version") do |ver|
      puts "Yasuo #{Scan_and_parse::VERSION}"
      exit
    end

  end.parse!(ARGV)

  unless options.input_file.length > 1 || options.ip_range.length > 1
    puts "To perform the Nmap scan, use the option -r to provide the network range\n"
    puts "Additionally, also provide the port number(s) or choose either option -pA to scan all ports or option -pD to scan top 1000 ports"
    puts "If you already have an Nmap scan output file in XML format, use -f to provide the file path and name\n\n"
    puts opts
    exit
  end

  # Passing the parsed options to the Scan and Parse class so that they can be used
  letsgo = Scan_and_parse.new(options.input_file, options.ip_range, options.port_range, options.default_ports_top, options.all_ports_all,options.brute)
  # logic to determine if scan is performed
  if options.input_file.length > 1
    letsgo.lameparse
  else
    puts "Initiating port scan"
    puts "----------------------\n"
    letsgo.lamescan
    letsgo.lameparse
  end
end

