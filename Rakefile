# -*- coding: utf-8 -*-

require 'bundler/gem_tasks'
require 'rake/clean'
require 'rake/testtask'
require 'rdoc/task'

Rake::TestTask.new do |task|
  if ((ENV.key? 'RUBY_DEBUG') && (! ENV['RUBY_DEBUG'].empty?)) then
    task.ruby_opts << '-d'
  end
end

Rake::RDocTask.new do |rd|
  rd.rdoc_files.include('lib/**/*.rb')
end

desc 'Build README.html from markdown source.'
task :readme => %w[ README.html ]

file 'README.html' do
  sh "markdown README.md >README.html"
end
CLOBBER.include 'README.html'

namespace :docker do
  desc 'setup docker container for unit-test.'
  task :setup do
    chdir('docker') do
      sh 'rake', 'setup'
    end
  end

  desc 'reset docker container for unit-test.'
  task :reset do
    chdir('docker') do
      sh 'rake', 'reset'
    end
  end

  desc 'start docker container for unit-test.'
  task :start do
    chdir('docker') do
      sh 'rake', 'docker:start'
    end
  end
end

# Local Variables:
# mode: Ruby
# indent-tabs-mode: nil
# End:
