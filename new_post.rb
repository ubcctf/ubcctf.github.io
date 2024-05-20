require "date"
require "optparse"
require 'json'
require 'shellwords'
require 'time'

options = {}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: new_post.rb -t TITLE"

  opts.on("-tTITLE", "--title=TITLE", "Title of the post") do |t|
    options[:title] = t
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end
parser.parse!

if options[:title].nil?
  puts parser.help
  exit
end

def to_slug(title)
  title.downcase.gsub(/ /, "-").gsub(/[^a-z0-9-]/, "")
end

date = Time.now
filename = "_posts/#{date.to_date.iso8601}-#{to_slug options[:title]}.md"

if File.exists?(filename)
  puts "Post already exists!"
  return
end

File.open(filename, "w") do |file|
  template = <<-EOF
---
layout: post
title: #{options[:title].to_json}
author: YOURNAMEHERE
date: #{date.iso8601}
---
EOF
  file.write(template)
end

editor = ENV['EDITOR'] || ENV['VISUAL'] || 'vim'

Process.exec("#{editor} #{filename.shellescape}")
