# encoding: UTF-8
require 'yajl_ext'

# = Extras
# We're not going to load these auotmatically, because you might not need them ;)
#
# require 'yajl/http_stream.rb' unless defined?(Yajl::HttpStream)
# require 'yajl/gzip.rb' unless defined?(Yajl::Gzip)
# require 'yajl/deflate.rb' unless defined?(Yajl::Deflate)
# require 'yajl/bzip2.rb' unless defined?(Yajl::Bzip2)

# = Yajl
#
# Ruby bindings to the excellent Yajl (Yet Another JSON Parser) ANSI C library.
module Yajl
  VERSION = "0.5.6"
  
  class Parser
    # A helper method for parse-and-forget use-cases
    #
    # +io+ is the stream to parse JSON from
    #
    # The +options+ hash allows you to set two parsing options - :allow_comments and :check_utf8
    #
    # :allow_comments accepts a boolean will enable/disable checks for in-line comments in the JSON stream
    #
    # :check_utf8 accepts a boolean will enable/disable UTF8 validation for the JSON stream
    def self.parse(io, options={}, read_bufsize=nil, &block)
      new(options).parse(io, read_bufsize, &block)
    end
  end
  
  class Encoder
    # A helper method for encode-and-forget use-cases
    #
    # Examples:
    #   Yajl::Encoder.encode(obj[, io, :pretty => true, :indent => "\t"])
    #
    #   output = Yajl::Encoder.encode(obj[, :pretty => true, :indent => "\t"])
    #
    # +obj+ is a ruby object to encode to JSON format
    #
    # +io+ is the optional IO stream to encode the ruby object to.
    # If +io+ isn't passed, the resulting JSON string is returned. If +io+ is passed, nil is returned.
    #
    # The +options+ hash allows you to set two encoding options - :pretty and :indent
    #
    # :pretty accepts a boolean and will enable/disable "pretty printing" the resulting output
    #
    # :indent accepts a string and will be used as the indent character(s) during the pretty print process
    def self.encode(obj, *args, &block)
      # TODO: this code smells, any ideas?
      options = {}
      io = nil
      args.each do |arg|
        if arg.is_a?(Hash)
          options = arg
        elsif arg.respond_to?(:read)
          io = arg
        end
      end if args.any?
      new(options).encode(obj, io, &block)
    end
  end
  
  # DEPRECATED - See Yajl::Parser and Yajl::Encoder
  module Stream
    # DEPRECATED - See Yajl::Parser
    def self.parse(io)
      STDERR.puts "WARNING: Yajl::Stream has be deprecated and will most likely be gone in the next release. Use the Yajl::Parser class instead."
      Parser.new.parse(io)
    end
    
    # DEPRECATED - See Yajl::Encoder
    def self.encode(obj, io)
      STDERR.puts "WARNING: Yajl::Stream has be deprecated and will most likely be gone in the next release. Use the Yajl::Encoder class instead."
      Encoder.new.encode(obj, io)
    end
  end
end