#!/usr/bin/env ruby

require "net/http"
require "net/https"
require "uri"
require 'nokogiri'
require 'mechanize'
require 'colorize'


# A simple wrapper around Mechanize to help automate brute forcing a login
# form on a webpage.
module LoginFormBruteForcer

  module_function

  # Returns an enumeration of usernames and passwords pulled from the supplied
  # text files. (Each line in the given files is expected to be a username
  # or password)
  def usernames_and_passwords(users_file="users.txt", password_file="pass.txt")
    Enumerator.new do |enum|
      File.open(users_file, "r").each do |user|
        File.open(password_file, "r").each do |password|
          enum.yield user, password
        end
      end
    end
  end

  # Attempts to bruteforce a login to supplied url.
  def bruteforce(url)
		user_found = "Not Found"
		pass_found = "Not Found"

		loginagent = Mechanize.new { |agent| agent.user_agent_alias = 'Mac Safari'}
		loginagent.verify_mode = OpenSSL::SSL::VERIFY_NONE
		loginagent.follow_meta_refresh = true

		loginform = loginagent.get(url).form(:name => /login/)

    # loginform could be nil in case of an exception or if the login form does
    # not exist. The precious check in Yasuo.rb is weak.
    if loginform.nil?
			puts "Login page not found. Looks like this instance maybe unauthenticated".green
		else
			username = loginform.field_with(name: /user|email|login|REGEMAIL|name/i)
			password = loginform.field_with(name: /pass|pwd|REGCODE/i)

      yatta = 0
      usernames_and_passwords.each do |user, pass|
        if yatta == 1; break end
        username.value = user.chomp
        password.value = pass.chomp
        begin
          puts "Trying combination --> #{username.value}/#{password.value}" #saurabh: comment this for less verbose output
          loginrequest = loginform.submit
          sleep 0.5
          if (loginrequest.body.scan(/"#{loginform.name}"/i).size == 0) &&
             (loginrequest.body.scan(/"#{username.name}"/i).size  == 0) &&
             (loginrequest.body.scan(/"#{password.name}"/i).size  == 0)
            yatta = 1
            user_found = user.chomp
            pass_found = pass.chomp
          end
        rescue Mechanize::ResponseCodeError => exception
          if (exception.response_code != '200' or exception.response_code != '301' or exception.response_code != '302')	#These response codes are handled by Mechanize
            loginrequest = exception.page
            puts "Invalid credentials or user does not have sufficient privileges".red
          else
            puts "Unknown server error".red
          end
        end
      end
      if yatta == 1
        puts "Yatta, found default login credentials - #{username.value} / #{password.value}\n".green
      else
        puts "Could not find default login credentials, sucks".red
      end
    end
    return user_found, pass_found
  end
end

