namespace :nagios do
  desc <<-DESC
  Sends summary emails to those users who have requested they get a summary email of their clicks periodically. By default, this is everyone.
  DESC
  task :send_ok => [:environment] do
    # make sure the params were passed correctly
    if ENV['nag_host'].nil? || ENV['monitored_host'].nil? || ENV['service'].nil? || ENV['msg'].nil?
      puts "Must pass params like this: rake nagios:send_ok nag_host=hostname monitored_host=this_hostname service=\"service-name\" msg=\"here's the message for the alert\""
    else  
      args = {
        :nscahost => ENV['nag_host'],
        :port => 5667,
        :hostname => ENV['nag_host'],
        :service => ENV['service'],
        :return_code => 0,
        :status => ENV['service']
      }
      nsca_connection = SendNsca::NscaConnection.new(args)
      nsca_connection.send_nsca
    end
  end

  desc <<-DESC
  Resets all accounts that are set up to receie weekly or daily summaries so that the next time the summaries job is run they receive their summary email
  DESC
  task :send_warning => [:environment] do
    # make sure the params were passed correctly
    if ENV['nag_host'].nil? || ENV['monitored_host'].nil? || ENV['service'].nil? || ENV['msg'].nil?
      puts "Must pass params like this: rake nagios:send_ok nag_host=hostname monitored_host=this_hostname service=\"service-name\" msg=\"here's the message for the alert\""
    else  
      args = {
        :nscahost => ENV['nag_host'],
        :port => 5667,
        :hostname => ENV['nag_host'],
        :service => ENV['service'],
        :return_code => 1,
        :status => ENV['service']
      }
      nsca_connection = SendNsca::NscaConnection.new(args)
      nsca_connection.send_nsca
    end
  end

  desc <<-DESC
  Resets a single account so that it will receive a summary email the next time the job is run. Pass account by email like this: rake email:reset_by_email email=account@email.com
  DESC
  task :send_critical => [:environment] do
    # make sure the params were passed correctly
    if ENV['nag_host'].nil? || ENV['monitored_host'].nil? || ENV['service'].nil? || ENV['msg'].nil?
      puts "Must pass params like this: rake nagios:send_ok nag_host=hostname monitored_host=this_hostname service=\"service-name\" msg=\"here's the message for the alert\""
    else  
      args = {
        :nscahost => ENV['nag_host'],
        :port => 5667,
        :hostname => ENV['nag_host'],
        :service => ENV['service'],
        :return_code => 2,
        :status => ENV['service']
      }
      nsca_connection = SendNsca::NscaConnection.new(args)
      nsca_connection.send_nsca
    end
 end
end