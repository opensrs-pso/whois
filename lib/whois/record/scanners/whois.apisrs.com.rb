#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2013 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/scanners/base'


module Whois
  class Record
    module Scanners

      class WhoisApisrsCom < Base

        self.tokenizers += [
            :skip_blank_line,
            :scan_available,
            :scan_keyvalue,
            :skip_lastupdate,
            :skip_fuffa,
        ]

        tokenizer :scan_available do
          if @input.scan(/No match for "(.+?)"\.\n/)
            @ast["Domain Name"] = @input[1].strip
            @ast["status:available"] = true
          end
        end
        
        tokenizer :skip_lastupdate do
          @input.skip(/>>>(.+?)<<<\n/)
        end

        tokenizer :skip_fuffa do
          @input.skip(/^\S(.+)\n/)
        end

      end

    end
  end
end
