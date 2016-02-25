#!/usr/local/bin/ruby
# coding: binary

module PurePack

  class << self

    MACHINE_ENDIAN_LITTLE = SYS.endian_little

    MACHINE_BYTE_SIZE = {
      :s => SYS.sizeof_short,     :S => SYS.sizeof_short,
      :i => SYS.sizeof_int,       :I => SYS.sizeof_int,
      :l => SYS.sizeof_long,      :L => SYS.sizeof_long,
      :q => SYS.sizeof_long_long, :Q => SYS.sizeof_long_long,
      :j => SYS.sizeof_pointer,   :J => SYS.sizeof_pointer,
    }

    BYTE_SIZE = {
      :c => 1, :C => 1,
      :s => 2, :S => 2,
      :l => (MACHINE_BYTE_SIZE[:l] ? 4 : nil),
      :L => (MACHINE_BYTE_SIZE[:L] ? 4 : nil),
      :q => (MACHINE_BYTE_SIZE[:q] ? 8 : nil),
      :Q => (MACHINE_BYTE_SIZE[:Q] ? 8 : nil),
      :i => MACHINE_BYTE_SIZE[:i], :I => MACHINE_BYTE_SIZE[:I],
      :j => MACHINE_BYTE_SIZE[:i], :J => MACHINE_BYTE_SIZE[:J],
      :n => 2, :v => 2,
      :N => (MACHINE_BYTE_SIZE[:l] ? 4 : nil),
      :V => (MACHINE_BYTE_SIZE[:l] ? 4 : nil),
    }

    WITH_ATTR_CMDS = MACHINE_BYTE_SIZE.select{|k, v| v}.keys

    CMD_INTEGER = BYTE_SIZE.select{|k, v| v}.keys

    CMD_ASCII = [:a, :A, :Z, :B, :b, :H, :h, :u, :m]

    CMD_MOVE = [:"@", :x, :X]

    CMD_OTHER = [:w, :U, :p, :P, :M] # not supprt p, P(pointer), U(UTF-8)  conversion yet

    BASE64 = Hash[
      ['A'..'Z','a'..'z', '0'..'9', ["+", "/", "="]].map(&:to_a).flatten.zip((0..64).to_a)
    ]

    BASE64_R = BASE64.invert

    BINARY = Hash[
      0,"0000", 1,"0001",  2,"0010",  3,"0011",  4,"0100",  5,"0101",  6,"0110",  7,"0111",
      8,"1000", 9,"1001", 10,"1010", 11,"1011", 12,"1100", 13,"1101", 14,"1110", 15,"1111"
    ]

    HEX = Hash[['0'..'9','A'..'F', ["\n"]].map(&:to_a).flatten.zip((0..16).to_a)]

    HEX_R = HEX.invert

    #
    # Unpack method
    #
    def unpack(str, template)
      r = [] ; cnt = 0 ; s = str.size

      analyze_template(template).each {|n|
        cmd, attr, size = [n[1], n[2], n[3]] ; cmd = cmd.to_sym

        if s == cnt
          r << (CMD_ASCII.include?(cmd) ? "" : nil)
          next
        end

        size = ((size == "*") ? s - cnt : ((size == "" ? 1 : size.to_i)))

        raise ArgumentError, "'#{attr}' allowed only after types #{WITH_ATTR_CMDS.join}" \
                             if (attr != "" && (not WITH_ATTR_CMDS.include?(cmd)))

        conv_func = nil ; ret_cnt = [0] ; options = []
        case cmd
        when *CMD_ASCII
          options = [cmd, n[3]]
          conv_func =
            case cmd
            when :a, :A, :Z     then :unpack_ascii
            when :b, :B, :h, :H then :unpack_bin
            when :u             then :unpack_uu
            when :m             then :unpack_base64
            end
        when *CMD_INTEGER # Numeric
          endian_little = MACHINE_ENDIAN_LITTLE
          endian_little = true  if attr.index("<")
          endian_little = false if attr.index(">")

          bytes = BYTE_SIZE[cmd]
          bytes = MACHINE_BYTE_SIZE[cmd] if (attr.index("_") || attr.index("!"))
          size = (size/bytes).to_i if n[3] == "*"

          options =
            case cmd
            when :c, :s, :i, :l, :q, :j then [true,  bytes, endian_little]
            when :C, :S, :I, :L, :Q, :J then [false, bytes, endian_little]
            when :n, :N                 then [false, bytes, false]
            when :v, :V                 then [false, bytes, true]
            end
          conv_func = :unpack_num
        when :g, :G, :e, :E, :D, :d, :F, :f # Float
          bytes = ([:g, :e, :F, :f].index(cmd)? 4 : 8)
          size = (size/bytes).to_i if n[3] == "*"

          options =
            case cmd
            when :e, :E         then [true,  bytes]
            when :g, :G         then [false, bytes]
            when :d, :f, :D, :F then [MACHINE_ENDIAN_LITTLE, bytes]
            end
          conv_func = :unpack_float
        when *CMD_OTHER
          option = [cmd, n[3]]
          case cmd
          when :w
            conv_func = :unpack_ber
          when :M
            conv_func = :unpack_qp
          end
        when *CMD_MOVE
          cnt =
            case cmd
            when :"@"
              case n[3] when "" then     0; when "*" then   str.size-cnt; else     n[3].to_i end
            when :x
              case n[3] when "" then cnt+1; when "*" then       str.size; else n[3].to_i+cnt end
            when :X
              case n[3] when "" then cnt-1; when "*" then 2*cnt-str.size; else n[3].to_i-cnt end
            end

          raise ArgumentError, "#{cmd} outsid of string" if (cnt < 0 || cnt > str.size)
        else
          # not support command but do nothing
        end
        r += send(conv_func, str, cnt, size, ret_cnt, options) if conv_func
        cnt += ret_cnt[0]
      }
      return r
    end

    #
    # Pack method
    #
    def pack(ary, template)
      r = "" ; cnt = 0 ; s = ary.size

      analyze_template(template).each {|n|
        cmd, attr, size = [n[1], n[2], n[3]] ; cmd = cmd.to_sym

        raise ArgumentError, "too few arguments" if ((not CMD_MOVE.include?(cmd)) && ary[cnt] == nil)

        raise ArgumentError, "'#{cmd}#{attr}' allowed only after types #{WITH_ATTR_CMDS.join}" \
                             if (attr != "" && (not WITH_ATTR_CMDS.include?(cmd)))

        size = ((size == "*") ?  s - cnt : ((size == "" ? 1 : size.to_i)))

        conv_func = nil ; ret_cnt = [0] ; options = []
        case cmd.to_sym
        when *CMD_ASCII
          raise TypeError, "No implicit conversion of #{ary[cnt].class} into String" \
                           unless ary[cnt].kind_of? String

          size = ary[cnt].size if (n[3] == "*")
          options = [cmd, n[3]]
          conv_func =
            case cmd
            when :a, :A, :Z     then :pack_ascii
            when :b, :B, :h, :H then :pack_bin
            when :u             then :pack_uu
            when :m             then :pack_base64
            end
        when *CMD_INTEGER # Numeric
          endian_little = MACHINE_ENDIAN_LITTLE
          endian_little = true  if attr.index("<")
          endian_little = false if attr.index(">")
          bytes =
            if (attr.index("_") || attr.index("!"))
              MACHINE_BYTE_SIZE[cmd]
            else
              BYTE_SIZE[cmd]
            end
          options =
            case cmd
            when :c, :s, :i, :l, :q, :j then [true,  bytes, endian_little]
            when :C, :S, :I, :L, :Q, :J then [true,  bytes, endian_little]
            when :n, :N                 then [false, bytes, false]
            when :v, :V                 then [false, bytes, true]
            end
          conv_func = :pack_num
        when :g, :G, :e, :E, :D, :d, :F, :f
          bytes = ([:g, :e, :F, :f].index(cmd)? 4 : 8)
          options =
            case cmd
            when :e, :E         then [true,  bytes]
            when :g, :G         then [false, bytes]
            when :d, :f, :D, :F then [MACHINE_ENDIAN_LITTLE, bytes]
            end
          conv_func = :pack_float
        when *CMD_OTHER
          case cmd
          when :w
            conv_func = :pack_ber
          when :M
            conv_func = :pack_qp
          end
        when *CMD_MOVE
          lcnt =
            case cmd
            when :"@"
              case n[3] when "" then        1; when "*" then      0; else n[3].to_i        end
            when :x
              case n[3] when "" then r.size+1; when "*" then r.size; else r.size+n[3].to_i end
            when :X
              case n[3] when "" then r.size-1; when "*" then r.size; else r.size-n[3].to_i end
            end

          raise ArgumentError, "#{cmd} outsid of string" if size < 0
          (r.size >= lcnt) ? r = r[0, lcnt] : r += "\x00" * (lcnt - r.size)
        else
            # not support command but do nothing
        end
        r <<  send(conv_func, ary, cnt, size, ret_cnt, options) if conv_func
        cnt += ret_cnt[0]
      }
      return r
    end

    #
    # Private Funcitons
    #
    private

    def num_to_bin(num) # same as "%08B" % num, num must be < 256
      a, b = (0xff & num).divmod(16); BINARY[a]+BINARY[b]
    end

    def num_to_hex(num) # same as "%02X" % num, num must be < 256
      a, b = (0xff & num).divmod(16); HEX_R[a]+HEX_R[b]
    end

    def int_split(i, n) # int_split(12345678, 1000) => [12, 345, 678]
      n = n.to_i ; r = [i] ; return r if (n == 0 || n == 1)
      r.unshift(*r.shift.divmod(n)) until r[0].abs < n.abs ; r
    end

    def str_nsplit(str, n) # str_nsplit("0123456789", 3) => ["012", "345", "678", "9]
      s  = [] ; o = 0 ; (s << str[o, n] ; o += n) while str[o] ; s
    end

    def analyze_template(str)
      r = [] ; cmd = "" ; attr = ""; size = "" ; state = :stop
      str.split("").each_with_index {|c, cnt|
        case c
        when 'a'..'z', 'A'..'Z', '@'
          r << [cmd+attr+size, cmd, attr, size] if(cmd != "")
          cmd = c ; attr = "" ; size = ""
        when  ' '
          r << [cmd+attr+size, cmd, attr, size] if(cmd != "")
          r << [" ", " ", "", ""] ;  cmd = "" ; attr = "" ; size = ""
        when '_', '!'
          if cmd == "" || size != "" || attr != ""
            raise ArgumentError, "Error Template, '#{str[0, cnt]} ^ #{str[cnt..-1]}'"
          end
          attr << c
        when '<', '>'
          if cmd == "" || size != "" || (not (attr == "" || attr == "!" || attr == "_"))
            raise ArgumentError, "Error Template, '#{str[0, cnt]} ^ #{str[cnt..-1]}'"
          end
          attr << c
        when '*'
          if cmd == "" || size != ""
            raise ArgumentError, "Error Template, '#{str[0, cnt]} ^ #{str[cnt..-1]}'"
          end
          r << [cmd+attr+"*", cmd, attr, "*"]
          cmd = "" ; attr = ""; size = ""
        when '0'..'9'
            if cmd == ""
              raise ArgumentError, "Error Template, '#{str[0, cnt]} ^ #{str[cnt..-1]}'"
            end
          size << c
        end
      }
      r << [cmd+attr+size, cmd, attr, size] if cmd != ""

      return r
    end

    #
    # Ascii
    #
    def unpack_ascii(str, offset, conv_size, ret_cnt, options=[])
      cmd, last_c = options
      r = str[offset, conv_size] ; ret_cnt[0] = r.size

      if cmd == :Z && (i = str.index("\x00"))
        r = r[0, i]
        ret_cnt[0] = i+1 if last_c == "*"
      elsif cmd == :A
        r = r[0..-2] while (r[-1] == " " || r[-1] == "\x00")
      end

      return [r]
    end

    #------------
    def pack_ascii(ary, offset, conv_size, ret_cnt, options)
      cmd, last_c = options
      r = ary[offset][0, conv_size]

      if cmd == :A
        r << " " * (conv_size - r.size)
      elsif cmd == :a
        r << "\x00" * (conv_size - r.size)
      else # cmd == :Z
        r << ((last_c == "*") ? "\x00" : "\x00" * (conv_size - r.size))
      end

      ret_cnt[0] = 1 ; r
    end

    #
    # Binary and Hex
    #
    def unpack_bin(str, offset, conv_size, ret_cnt, options)
      cmd, last_c = options

      binary = ((cmd == :b) || (cmd == :B)) ? true : false
      invert = ((cmd == :b) || (cmd == :h)) ? true : false
      bits   = binary ? 8 : 2
      conv_size = conv_size * bits if last_c == "*"
      byte_size = ((conv_size + (bits-1)) / bits).to_i

      r = str[offset, byte_size].bytes.map{|n|
        binary ?
        (invert ? num_to_bin(n).reverse : num_to_bin(n)) :
        (invert ? ("%02x" % n).reverse : ("%02x" % n))
      }.join[0, conv_size]

      ret_cnt[0] = ((r.size+(bits-1))/bits).to_i ; [r]
    end

    #------------
    def pack_bin(ary, offset, conv_size, ret_cnt, options)
      cmd, = options
      r = "" ; ret_cnt[0] = 1

      binary = ((cmd == :b) || (cmd == :B)) ? true : false
      invert = ((cmd == :b) || (cmd == :h)) ? true : false
      bits   = binary ? 8 : 2

      str_nsplit(ary[offset][0,conv_size], bits).map {|n|
        n = (n + "0"*(bits-1))[0,bits]
        n.reverse! if invert
        (binary ? n.to_i(2) : n.hex).chr
      }.join
    end

    #
    # UU-encode
    #
    def unpack_uu(str, offset, conv_size, ret_cnt, options)
      unless (str[offset]).between?(" ", "`")
        ret_cnt[0] = 0
        return [""]
      end

      r = "" ; cnt = 0
      while (c =  str[offset+cnt])
        break unless (c.between?(" ", "`") || (c == "\n"))
        r << c ; cnt += 1
      end

      r = r.split("\n").map {|n|
        data_size = n.slice!(0,1).ord - 0x20
        pack_bin([n.bytes.map{|m| num_to_bin(m-0x20)[-6..-1]}.join], 0, data_size*8, [], [:B])[0, data_size]
      }.join

      ret_cnt[0] = cnt ; [r]
    end

    #------------
    def pack_uu(ary, offset, conv_size, ret_cnt, options)
      ret_cnt[0] = 1

      if (a = ary[offset]) == ""
        ""
      else
        a += "\x00" * (2 - ((a.size + 2)%3)) # add padding

        a = str_nsplit(unpack_bin(a, 0, a.size, [], [:B, "*"])[0], 6).map{|n|
        (n.to_i(2)+0x20).chr}.join.gsub(" ", "`")

        str_nsplit(a, 60).map {|n|
          ((n.size * 3 / 4).to_i + 0x20).chr + n + "\n"
        }.join
      end
    end

    #
    # Q Printable
    #
    def unpack_qp(str, offset, conv_size, ret_cnt, options)
      (ret_cnt[0] = 0 ; return [""]) unless str[offset]

      r = "" ; esc = nil ; cnt = 0
      while (c = str[offset+cnt])
        (esc=nil ; next) if esc == "=\n"
        (r << esc[1,2].hex.chr ; esc=nil) if esc && (esc.size == 3)
        if esc && HEX[c]
          esc << c
        elsif esc && (not HEX[c])
          r << esc << c ; esc=nil
        else
          c == "=" ? esc = c : r << c
        end
        cnt += 1
      end

      ret_cnt[0] = cnt ; [r]
    end

    #------------
    def pack_qp(ary, offset, conv_size, ret_cnt, options)
      return "" if (a = ary[offset]) == ""

      r = "" ; cnt = 0
      while (c = a[cnt])
        case c
        when "\t"
          r << c
        when "\n"
          r << "=\n" if r[-1] == "\t" || r[-1] == " "
          r << c
        when "="
          r << "=3D"
        when " ".."~"
          r << c
        else
          r << "=" << num_to_hex(c.ord)
        end
        cnt += 1
      end
      r << "=\n" if r[-1] != "\n"

      ret_cnt[0] = 1 ; r
    end

    #
    # Base64
    #
    def unpack_base64(str, offset, conv_size, ret_cnt, options)
      r = "" ; cnt = 0

      cnt+=1 if BASE64[str[offset+cnt]] == nil

      rr = ""
      while (c = str[offset+cnt])
        d = BASE64[c] ; cnt += 1
        raise ArgumentError, "invalid base64" if (conv_size == 0) && (d == nil)
        next if (c == "\n") || (d == nil) || (d == 64) # ignore this, 64 is "="

        (rr << num_to_bin(d)[-6..-1])
        (r << rr.slice!(0,8).to_i(2).chr) if rr.size >= 8
      end

      ret_cnt[0] = cnt ; [r]
    end

    #------------
    def pack_base64(ary, offset, conv_size, ret_cnt, options)
      cmd, last_c = options
      ret_cnt[0] = 1

      if (a = ary[offset]) == ""
        ""
      else
        r = "" ; rr = ""
        a.size.times {|n|
          rr << num_to_bin(a[n].ord)
          r  << BASE64_R[rr.slice!(0,6).to_i(2)] if rr.size >= 6
          r  << BASE64_R[rr.slice!(0,6).to_i(2)] if rr.size >= 6
        }
        r << BASE64_R[(rr+"00000")[0,6].to_i(2)] if rr != ""
        r = r+("="*(3-((r.size+3)%4)))

        if conv_size == 0
          r
        else
          if last_c == "*" || last_c == ""
            split_size = 60
          else
            split_size = (last_c.to_i/3).to_i * 4
            split_size = 60 if split_size == 0
          end
          str_nsplit(r, split_size).join("\n") << "\n"
        end
      end
    end

    #
    # BER-compressed
    #
    def unpack_ber(str, offset, conv_size, ret_cnt, options)
      cmd, last_c = options
      r = [] ; cnt = 0

      conv_size.times {
        n = 0
        begin
          c = (0xff & str[offset+cnt].ord)
          n = n * 128 + (0x7f & c) ; cnt += 1
        end while c > 127
        r << n
      }
      ret_cnt[0] = cnt ; r
    end

    #------------
    def pack_ber(ary, offset, conv_size, ret_cnt, options)
      r = "" ; cnt = 0

      conv_size.times{|i|
        raise ArgumentError, "too few arguments" if ary[offset+i] == nil

        n = int_split(ary[offset+i], 128)
        r << ((n.size-1).times.map{|m| (n[m]+128).chr}.join+n[-1].chr)
        cnt += 1
      }
      ret_cnt[0] = cnt ; r
    end

    #
    # Integer
    #
    def unpack_num(str, offset, conv_size, byte_cnt, options)
      signed, byte_size, endian_little = options
      r = [] ; cnt = 0 ; bit_size = byte_size*8

      conv_size.to_i.times {|i|
        n = str[offset+i*byte_size, byte_size]
        (r << nil ; next) if (n == nil) || (n == "") || (n.size != byte_size)

        n.reverse! if endian_little ; n = n.bytes
        n[0] -= 256 if (signed && (n[0] > 127))
        r << n.inject(0){|x, m| x*256 + m}
        raise RangeError, "cannot unpack to Fixnum: 0x#{n.map{|m| "%02x" % m}.join}" \
                          unless r[-1].kind_of? Integer

        cnt += byte_size
      }
      byte_cnt[0] = cnt ; r
    end

    #------------
    def pack_num(ary, offset, conv_size, ret_cnt, options)
      signed, byte_size, endian_little = options
      r = "" ; cnt = 0

      conv_size.times {|i|
        raise ArgumentError, "too few arguments" if ary[offset+i] == nil

        n = int_split(ary[offset+i], 256)
        n = n.size >= byte_size ? n[0, byte_size] : (n[0] < 0 ? [-1] : [0])*(byte_size-n.size)+n
        n.reverse! if endian_little
        n.each{|m| r << (0xff & m).chr}

        cnt += 1
      }
      ret_cnt[0] = cnt ; r
    end

    #
    # Float, IEEE754 32 and 64 bits float
    #
    def unpack_float(str, offset, conv_size, byte_cnt, options)
      endian_little, byte_size = options
      r = [] ; cnt = 0
      exp_bits, frac_bits, exp_off = ((byte_size == 4) ? [8, 23, 127] : [11, 52, 1023])

      conv_size.times {|i|
        n = str[offset+i*byte_size, byte_size]
        (r << nil ; next) if (n == nil) || (n == "") || (n.size != byte_size)

        n.reverse! if endian_little

        n = n.bytes.map{|n| num_to_bin(n)}.join
        sign = n[0].to_i
        exp = n[1, exp_bits].to_i(2)
        frac = n[1+exp_bits, frac_bits].to_i(2)

        r <<
        if exp == 0 && frac == 0 # zero
          (-1)**sign * 0.0
        elsif exp == exp_off # inf or nan
          frac == 0 ? ((-1)**sign * 1/0.0) : (0.0/0.0)
        else
          (exp == 0) ? (frac_off = 0.0 ; exp += 1) : frac_off = 1.0
          ((-1)**sign) * (frac_off + (frac.to_f / 2**(frac_bits))) * (2**(exp - exp_off))
          end
        cnt += byte_size
      }
      byte_cnt[0] = cnt ; r
    end

    #------------
    def pack_float(ary, offset, conv_size, byte_cnt, options)
      endian_little, byte_size = options
      r = "" ; cnt = 0
      exp_bits, frac_bits, exp_off = ((byte_size == 4) ? [8, 23, 127] : [11, 52, 1023])

      conv_size.times {|i|
        raise ArgumentError, "too few arguments" if ary[offset+i] == nil

        f = ary[offset+i].to_f
        sign = (f.to_s[0] == "-" ? "1" : "0")

        if f == 0
          exp = "0" * exp_bits ; frac = "1" + "0" * frac_bits
        elsif f.infinite?
          exp = "1" * exp_bits ; frac = "1" + "0" * frac_bits
        elsif f.nan?
          exp = "1" * exp_bits ; frac = "11" + "0" * (frac_bits-1)
        else
          frac, exp = Math.frexp(f) ; frac = frac.abs ; n = ""

          (frac_bits+2).times {
            frac *= 2 ; n << frac.to_i.to_s ; frac -= 1 if frac >= 1
          }
          n = "%B" % (n.to_i(2)+1) if n[-2,2] == "11"
          frac =
            if (exp + exp_off) <= 0
              (exp+=1 ; n = "0" + n) while (exp + exp_off) <= 0
              n[0, frac_bits]
            else
              n[1, frac_bits]
            end
          exp = ("%0#{exp_bits}B" % (exp + exp_off - 1))
        end
        n = str_nsplit((sign + exp + frac), 8).map{|n| n.to_i(2).chr}.join
        r << (endian_little ? n.reverse : n)
        cnt += 1
      }
      byte_cnt[0] = cnt ; r
    end
  end

end

#
# String unpack
#
class String

  alias :unpack_org :unpack  if (("".respond_to? :unpack) && (not ("".respond_to? :unpack_org)))
  def unpack(template)
    PurePack.unpack(self, template)
  end

end

#
# Array Pack
#
class Array

  alias :pack_org :pack  if (([].respond_to? :pack) && (not ([].respond_to? :pack_org)))
  def pack(template)
    PurePack.pack(self, template)
  end

end
