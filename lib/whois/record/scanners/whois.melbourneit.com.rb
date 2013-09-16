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

      class WhoisMelbourneitCom < Base

        self.tokenizers += [
            :scan_available,
            :scan_keyvalue,
            # :skip_lastupdate,
            # :skip_fuffa
        ]


        tokenizer :scan_available do
          if @input.scan(/^Not found: (.+)\n/)
            @ast["Domain Name"] = @input[1]
            @ast["status:available"] = true
          end
        end

        # tokenizer :skip_lastupdate do
        #   @input.skip(/>>>(.+?)<<<\n/)
        # end

        # tokenizer :skip_fuffa do
        #   @input.skip(/^\S(.+)\n/)
        # end


        # Scan a key/value pair and stores the result in the current target.
        # target is the global @ast if no '_section' is set, else '_section' is used.
        tokenizer :scan_keyvalue do
          if @input.scan(/\s*(.+?)\.+\s(.*?)\n/)
            key, value = @input[1].strip, @input[2].strip
            target = @tmp['_section'] ? (@ast[@tmp['_section']] ||= {}) : @ast
            if target[key].nil?
              target[key] = value
            else
              target[key] = Array.wrap(target[key])
              target[key] << value
            end
          end
          # p target
        end

      end

    end
  end
end