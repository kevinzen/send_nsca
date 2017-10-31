$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
require 'send_nsca'
#require 'spec'
#require 'spec/autorun'

RSpec.configure do |config|
	config.expect_with(:rspec) { |c| c.syntax = :should }  
end
