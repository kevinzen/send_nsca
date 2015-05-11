require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = 'send_nsca'
    gem.summary = 'A ruby gem for sending passive alerts to Nagios through NSCA.'
    gem.description = 'A pure ruby implementation of the send_nsca program for sending passive alerts to Nagios through NSCA.'
    gem.email = 'kbedell@gmail.com'
    gem.homepage = 'http://github.com/kevinzen/send_nsca'
    gem.authors = ['kevinzen', 'kyrremann']
    gem.add_development_dependency 'rspec', '>= 1.2.9'
    gem.require_path = 'lib'
    gem.files        = %w(History.txt install.rb MIT-LICENSE.txt README.rdoc Rakefile) + Dir['lib/**/*'] + Dir['spec/**/*']
    gem.test_files   = Dir['spec/**/*']
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts 'Jeweler (or a dependency) not available. Install it with: gem install jeweler'
end


require 'rspec/core/rake_task'

task :default => [:spec]

desc 'Run the specs.'
RSpec::Core::RakeTask.new do |spec|
  spec.pattern = 'spec/**/*_spec.rb'
end

