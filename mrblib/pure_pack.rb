#!/usr/local/bin/ruby

if Object.const_defined? :MRUBY_VERSION
  class Integer
    def to_int ; self ; end
  end

  class String
    def b ; self ; end
  end

  module Kernel
    def warn(*a) ; end
  end
end

module PurePack

  unless PurePack.const_defined? :SIZEOF # for debug
    module SIZEOF
      class << self
        def endian_little
          true # ("\x00\x01".unpack("S")[0] > 1)
        end

        def short
          2 # [0].pack("s!").size
        end

        def int
          4 # [0].pack("i!").size
        end

        def long
          8 # [0].pack("l!").size
        end

        def long_long
          8 # [0].pack("q!").size
        end

        def float
          4
        end

        def double
          8
        end

        def pointer
          8 # [0].pack("j!").size
        end
      end
    end

    # move to C
    def PurePack.str_to_float(str)
      str.orig_unpack(str.size == 4 ? "g" : "G")[0]
    end

    # move to C
    def PurePack.float_to_str(num, byte_size)
      [num].orig_pack(byte_size == 4 ? "g" : "G")
    end

  end

  BYTE_SIZE_NATIVE = {
      :s => SIZEOF.short,     :S => SIZEOF.short,
      :i => SIZEOF.int,       :I => SIZEOF.int,
      :l => SIZEOF.long,      :L => SIZEOF.long,
      :q => SIZEOF.long_long, :Q => SIZEOF.long_long,
      :j => SIZEOF.pointer,   :J => SIZEOF.pointer,
      :f => SIZEOF.float,     :F => SIZEOF.float,
      :d => SIZEOF.double,    :D => SIZEOF.double,
  }

  BYTE_SIZE = {
    :c => 1, :C => 1, :s => 2, :S => 2, :l => 4, :L => 4,
    :n => 2, :N => 4, :v => 2, :V => 4,
    :e => 4, :E => 8, :g => 4, :G => 8,
  }

  # Support Command
  CMD_ASCII   = [:a, :A, :Z]
  CMD_BINHEX  = [:B, :b, :H, :h]
  CMD_POINTER = [:p, :P] # not support
  CMD_OTHER   = [:u, :m, :M, :w, :U] #uu, base64, q-print, ber, UTF8

  WITH_ATTR_CMD = [:s, :S, :i, :I, :l, :L, :q, :Q, :j, :J]
  CMD_INTEGER   = [:c, :C, :n, :N, :v, :V].push(*WITH_ATTR_CMD)

  NATIVE_CMD_FLOAT = [:D, :d, :F, :f]
  CMD_FLOAT        = [:g, :G, :e, :E].push(*NATIVE_CMD_FLOAT)

  CMD_MOVE = [:"@", :x, :X]

  # Errors
  ARG_ERR = ->(s) {
    raise ArgumentError, "'#{s[0]}' allowed only after types #{WITH_ATTR_CMD.join}"
  }
  ARG_ERR_NOS = ->(s) {
    raise ArgumentError, "% is not supported"
  }
  RNG_ERR = ->(s) {
    raise RangeError, "Can't use both '<' and '>'"
  }
  RNG_ERR_OVR = ->(s) {
    raise RangeError, "#{s} length too bit"
  }
  RNG_ERR_FLT = ->(s) { # only mrury
    raise RangeError, "cannot unpack to Fixnum: 0x#{s.unpack("H*")[0]}"
  }
  OUT_ERR = ->(s) {
    raise ArgumentError, "#{s} outside of string"
  }
  ARG_FEW_ERR = ->(s) {
    raise ArgumentError, "too few arguments"
  }
  ARG_BASE64_ERR = ->(s) {
    raise ArgumentError, "invalid base64"
  }
  ARG_UTF8_ERR = ->(s) {
    raise ArgumentError, "malformed UTF-8 character"+(s ? s : "")
  }
  ARG_UTF8_RED_ERR = ->(s) {
    raise ArgumentError, "redundant UTF-8 sequence"
  }
  RNG_PACK_ERR = ->(s) {
    raise RangeError, "pack(U): value out of range"
  }
  RUN_CHG_ERR = ->(s) {
    raise RuntimeError, "format string modified"
  }
  ARG_NEG_ERR = ->(s) {
    raise ArgumentError, "can't compress negative numbers"
  }

  # scan pattern
  SCAN = /([A-Za-z\n%@#])([!_]?[<>]?)([*0-9]*)/m

  class << self

    #
    # Int
    #
    def str_to_int(str, signed)
      init = ((signed && (str[0].b.ord >= 0x80)) ? -1 : 0)
      str.bytes.inject(init) {|r, n| r*256+n}
    end

    # unpack
    def unpack_int(cmd, attr, cnt, str, offset)
      return [] if cnt == 0

      str_index = offset[0]
      signed = !!cmd.to_s.match(/[a-mo-uw-z]/) # remove :n and :v

      byte_size = BYTE_SIZE[cmd] || BYTE_SIZE_NATIVE[cmd]
      byte_size = BYTE_SIZE_NATIVE[cmd] if !!attr.match(/[_!]/)

      if (str.size - str_index) < byte_size
        return (cnt == "*" ? [] : [nil]*cnt)
      end

      reverse_byte = SIZEOF.endian_little
      reverse_byte = false if attr.index(">") || [:n, :N, :c, :C].include?(cmd)
      reverse_byte = true  if attr.index("<") || [:v, :V].include?(cmd)

      r = []
      cnt = (str.size / byte_size).to_i if cnt == "*"
      cnt.times {|n|
        s = str.slice(str_index+n*byte_size, byte_size)
        r << (s.size < byte_size ? nil : str_to_int((reverse_byte ? s.reverse : s), signed))
        RNG_ERR_FLT.call(s) if r[-1].instance_of? Float
      }
      offset[0] = str_index + r.size*byte_size

      return r
    end

    def int_to_str(num, byte_size)
      r = ""
      byte_size.times {|n|
        num, m = num.to_int.divmod(256)
        r.insert(0, m.chr)
      }
      return r
    end

    # pack
    def pack_int(cmd, attr, cnt, ary, offset)
      return "" if cnt == 0

      ary_index = offset[0]
      byte_size = BYTE_SIZE[cmd] || BYTE_SIZE_NATIVE[cmd]
      byte_size = BYTE_SIZE_NATIVE[cmd] if !!attr.match(/[_!]/)

      reverse_byte = SIZEOF.endian_little
      reverse_byte = false if attr.index(">") || [:n, :N, :c, :C].include?(cmd)
      reverse_byte = true  if attr.index("<") || [:v, :V].include?(cmd)

      r = ""
      cnt = ary.size if cnt == "*"
      cnt.times {
        num = ary[ary_index]
        ARG_FEW_ERR.call(nil) if num == nil
        s = int_to_str(num, byte_size)
        r << (reverse_byte ? s.reverse : s)
        ary_index += 1
      }
      offset[0] = ary_index

      return r
    end

    #
    # Float
    #

    # unpack
    def unpack_float(cmd, attr, cnt, str, offset)
      return [] if cnt == 0

      str_index = offset[0]
      byte_size = BYTE_SIZE_NATIVE[cmd] || BYTE_SIZE[cmd]

      if (str.size - str_index) < byte_size
        return (cnt == "*" ? [] : [nil]*cnt)
      end

      reverse_byte = SIZEOF.endian_little
      reverse_byte = false if [:g, :G].include?(cmd)
      reverse_byte = true  if [:e, :E].include?(cmd)

      r = []
      cnt = (str.size / byte_size).to_i if cnt == "*"
      cnt.times {|n|
        s = str.slice(str_index+n*byte_size, byte_size)
        break if s.size < byte_size
        r.push(str_to_float(reverse_byte ? s.reverse : s))
      }
      offset[0] = str_index + r.size*byte_size

      return r
    end

    # pack
    def pack_float(cmd, attr, cnt, ary, offset)
      return "" if cnt == 0

      ary_index = offset[0]
      byte_size = BYTE_SIZE_NATIVE[cmd] || BYTE_SIZE[cmd]

      reverse_byte = SIZEOF.endian_little
      reverse_byte = false if [:g, :G].include?(cmd)
      reverse_byte = true  if [:e, :E].include?(cmd)

      r = ""
      cnt = ary.size if cnt == "*"
      cnt.times {
        num = ary[ary_index]
        ARG_FEW_ERR.call(nil) if num == nil
        s = float_to_str(num, byte_size)
        r << (reverse_byte ? s.reverse : s)
        ary_index += 1
      }
      offset[0] = ary_index

      return r
    end

    #
    # Ascii
    #

    # unpack
    def unpack_ascii(cmd, attr, cnt, str, offset)
      return [""] if cnt == 0

      str_index = offset[0]

      # cmd == :a
      r_str = str[str_index, cnt == "*" ? str.size : cnt]
      offset[0] = str_index + r_str.size

      if cmd == :Z && (i = r_str.index("\x00"))
        r_str.slice!(i, r_str.size)
        offset[0] = str_index+i+1 if cnt == "*"
      elsif cmd == :A
        r_str.chop! while (r_str[-1] == " " || r_str[-1] == "\x00")
      end

      return [r_str]
    end

    # pack
    def pack_ascii(cmd, attr, cnt, ary, offset)
      ary_index = offset[0]
      r = (cnt == "*" ? ary[ary_index].to_s : ary[ary_index].to_s[0, cnt])

      if cmd == :Z
        r << ((cnt == "*") ? "\x00" : "\x00" * (cnt - r.size))
      else
        r << (cmd == :A ? " " : "\x00") * (cnt - r.size) unless cnt == "*"
      end
      offset[0] = ary_index+1

      return r
    end

    #
    # BinHex
    #

    # unpack
    def unpack_binhex(cmd, attr, cnt, str, offset)
      r = String.method_defined?(:encoding) ? "".force_encoding(Encoding::US_ASCII) : ""
      return [r] if cnt == 0

      str_index = offset[0]
      bits = (((cmd == :b) || (cmd == :B)) ? 8 : 2)
      reverse = ((cmd == :b) || (cmd == :h))
      cnt = str[str_index..-1].size*bits if cnt == "*"
      byte_cnt = ((cnt+(bits-1))/ bits).to_i
      offset[0] = str_index+byte_cnt

      f = (bits == 8 ? "%08B" : "%02x")
      byte_cnt.times {|i|
        break unless (c = str[str_index+i])
        s = "#{f}" % c.ord
        r << (reverse ? s.reverse : s)
      }

      return [r[0, cnt]]
    end

    # pack
    def pack_binhex(cmd, attr, cnt, ary, offset)
      ary_index = offset[0]
      bits = (((cmd == :b) || (cmd == :B)) ? 8 : 2)
      reverse = ((cmd == :b) || (cmd == :h))
      str = ary[ary_index]
      cnt = str.size if cnt == "*"
      str = str[0, cnt]

      r = ""
      while cnt > 0 do
        n = str.slice!(0, bits)
        cnt -= ((bits == 2 || n.empty? ) ? 2 : n.size)
        n = n + "0"*(bits - n.size)
        n.reverse! if reverse
        r << (bits == 8 ? n.to_i(2) : n.hex).chr
      end
      offset[0] = ary_index+1

      return r
    end

    #
    # Move
    #

    # unpack
    def unpack_move(cmd, attr, cnt, str, offset)
      str_index = offset[0]

      offset[0] =
        case [cmd, cnt == "*"]
        when [:"@", true]
          str.size - str_index
        when [:"@", false]
          cnt
        when [:x, true]
          str.size
        when [:x, false]
          str_index + cnt
        when [:X, true]
          2*str_index - str.size
        when [:X, false]
          str_index - cnt
        end
      OUT_ERR.call(cmd) if offset[0] < 0 || offset[0] > str.size
    end

    # pack
    def pack_move(cmd, attr, cnt, str)
      cnt = 0 if cnt == "*"
      abs_pos =
        case cmd
        when :"@"
          cnt
        when :x
          str.size + cnt
        when :X
          str.size - cnt
        end
      OUT_ERR.call(cmd) if abs_pos < 0
      if (str.size > abs_pos)
        str[abs_pos..-1] = ""
      else
        str << "\x00"*(abs_pos - str.size)
      end
    end

    #
    # Other
    #

    # check and convert uuencode data
    def uu_range_check(c)
      case c
      when 0..0x40
        c == 0 ? "`" : (c + 0x20).chr # replace " " to "`"
      when " ".."`"
        "%06B" % ((c.ord ^ 0x20) & 0x3f)
      else
        nil
      end
    end

    # check and convert base64 data
    def base64_range_check(c)
      case c
      when 0..25
        (65+c).chr # 65.chr == "A"
      when 26..51
        (97+c-26).chr # 97.chr == "a"
      when 52..61
        (48+c-52).chr # 48.chr == "0"
      when 62
        "+"
      when 63
        "/"
      #---
      when 'A'..'Z'
        ("%08B" % (c.ord - 65))[-6, 6]
      when 'a'..'z'
        ("%08B" % (c.ord - 97 + 26))[-6, 6]
      when '0'..'9'
        ("%08B" % (c.ord - 48 + 52))[-6, 6]
      when '+'
        "111110"
      when '/'
        "111111"
      else
        nil
      end
    end

    # unpack uu and base64
    def unpack_uu64(cmd, attr, cnt, str, offset)
      str_index = offset[0]

      strict = (cnt == 0) && (cmd == :m)
      r = ""
      s = ""
      s4 = ""
      data_cnt = ((cmd == :m) ? 3 : nil)
      while str[str_index]
        c = ((cmd == :m) ? base64_range_check(str[str_index]) : uu_range_check(str[str_index]))
        str_index += 1

        if c
          if data_cnt == nil # set data count for uuencode
            break if c == "000000" # bad data count
            data_cnt = c.to_i(2)
            next
          end

          s4 << c
          s << pack_binhex(:B, "", "*", [s4.slice!(0, 24)], [0]) if s4.size == 24
          r << s.slice!(0, s.size)[0, data_cnt] if s.size >= data_cnt
        else # c == nil
          if str[str_index-1] == "=" && cmd == :m # term char
            str_index -= 1
            break
          end
          ARG_BASE64_ERR.call(nil) if strict

          unless r.empty?  # remove term char and reset state
            s = ""
            s4 = ""
            data_cnt = ((cmd == :m) ? 3 : nil)
            next
          end

          break if data_cnt == nil  # bad char on top
          s4 << "000000" if cmd == :u
        end
      end
      if strict && !s4.empty? # check data size and term char for :m0
        ARG_BASE64_ERR.call(nil) if s4.size < 8
        rest_byte = (s4.size < 16 ? 2 : 1)
        term = str[str_index, str.size]
        ARG_BASE64_ERR.call(nil) if term.size  != rest_byte
        ARG_BASE64_ERR.call(nil) if term       != "="*rest_byte
        ARG_BASE64_ERR.call(nil) if s4[-2..-1] != "00" # bad padding
      end
      s4 << "00" if cmd == :u # for "\"\n".unpack("u") => ["\x00"]
      r << pack_binhex(:B, "", (s4.size < 16) ? 8 : 16, [s4+"00"], [0])[0, data_cnt] if s4.size >= 8
      offset[0] = str_index

      return [r.b]
    end

    # pack uu and base64
    def pack_uu64(cmd, attr, cnt, ary, offset)
      ary_index = offset[0]
      offset[0] = ary_index+1
      str = ary[ary_index]
      return "" if str.empty?

      strict = (cnt == 0) && (cmd == :m)
      cnt = ((cnt == "*" ? 1 : cnt) / 3).to_i * 3
      cnt = (cmd == :u ? 63 : 66) if cnt > (cmd == :u ? 63 : 66) # max cnt
      cnt = 45 if cnt == 0

      str.scan(/.{1,#{cnt}}/).map {|s|
        header = (cmd == :u ? ((s.size.to_i)+0x20).chr : "")
        body = unpack_binhex(:B, "", "*", s, [0])[0].scan(/.{1,6}/).map {|n|
          n << "0" * (6-n.size)
          (cmd == :u) ? uu_range_check(n.to_i(2)) : base64_range_check(n.to_i(2))
        }.join
        padding = (cmd == :u ? "`" : "=")*(2-((s.size+2)%3)) + (strict ? "" : "\n")
        header +body + padding
      }.join
    end

    # unpack ber
    def unpack_ber(attr, cnt, str, offset)
      str_index = offset[0]
      cnt = str.size - str_index if cnt == "*"
      r = []

      cnt.times {
        n = 0
        while (c = str[str_index])
          str_index += 1
          c = 0xff & c.ord
          n = n * 128 + (0x7f & c)
          (r << n ; break) if c < 128
        end
      }
      offset[0] = str_index

      return r
    end

    # pack ber
    def pack_ber(attr, cnt, ary, offset)
      ary_index = offset[0]

      r = ""
      cnt.times {
        num = [ary[ary_index]]
        ARG_FEW_ERR.call(attr) if num[0] == nil
        ARG_NEG_ERR.call(nil)  if num[0] < 0
        num[0] + 0 # check arg is integer
        num[0,1] = num[0].divmod(128) while num[0] >= 128
        r << num[0,num.size-1].map {|n| (n+128).to_i.chr}.join+num[-1].to_i.chr
        ary_index += 1
      }
      offset[0] = ary_index

      return r
    end

    # unpack q-print
    def unpack_qp(attr, cnt, str, offset)
      str_index = offset[0]

      r = ""
      loop do
        break if str[str_index] == nil
        (str_index+=2 ; next) if str[str_index, 2] == "=\n"
        (str_index+=3 ; next) if str[str_index, 3] == "=\r\n"

        if !!(str[str_index, 3].match(/=[[:xdigit:]]{2}/))
          r << str[str_index+1,2].hex.chr
          str_index += 3
        elsif str[str_index] == "=" # invalid string
          r << str[str_index, str.size]
          break
        else
          r << str[str_index]
          str_index += 1
        end
      end
      offset[0] = str_index

      return [r.b]
    end

    # pack q-print
    def pack_qp(attr, cnt, ary, offset)
      ary_index = offset[0]
      str = ary[ary_index]

      r = ""
      cnt = 0
      chr_cnt = 0
      while (c = str[cnt])
        case c
        when "\t", " ".."~"
          r << c
          chr_cnt += 1
          (r << "3D" ; chr_cnt += 2) if c == "="
        when "\n"
          (r << "=\n" ; chr_cnt += 3) if r[-1] == "\t" || r[-1] == " "
          r << c
          chr_cnt += 1
        else
          r << "=" << ("%02X" % c.ord)
          chr_cnt += 3
        end
        (r << "=\n" ; chr_cnt = 0) if chr_cnt >= 73
        cnt += 1
      end
      r << "=\n" unless r[-3, 3] == "=\n"
      offset[0] = ary_index + 1

      return r
    end

    # unpack utf8, unicode <-> utf8 convert
    def unpack_utf8(attr, cnt, str, offset)
      str_index = offset[0]
      cnt = str.size - str_index if cnt == "*"

      r = []
      cnt.times {
        break unless (c = str[str_index])
        str_index += 1

        c = c.ord
        (r << c ; next) if c <= 0x7f

        c = ("%08B" % c)
        byte_size = c.index("0")
        ARG_UTF8_ERR.call(nil) if byte_size == nil || byte_size == 1 || byte_size > 7
        c[0, byte_size] = "" # delete first n bits

        (byte_size-1).times {|n|
          cc = str[str_index]
          str_index += 1
          ARG_UTF8_ERR.call("(expected #{byte_size} bytes, given #{n+1} bytes)") unless cc
          cc = ("%08B" % cc.ord)
          ARG_UTF8_ERR.call(nil) if cc.slice!(0,2) != "10"
          c << cc
        }
        ARG_UTF8_RED_ERR.call(nil) if c[0, 6].to_i(2) == 0
        r << c.to_i(2)
      }
      offset[0] = str_index

      return r
    end

    # pack utf8, unicode <-> utf8 convert
    def pack_utf8(attr, cnt, ary, offset)
      ary_index = offset[0]

      r = ""
      cnt.times {
        i = [ary[ary_index]]
        ary_index += 1
        ARG_FEW_ERR.call(nil) unless i
        RNG_PACK_ERR.call(nil) if i[0] < 0

        if i[0] <= 0x7f
          r << i[0].chr
        else
          i[0,1] = i[0].divmod(64) while i[0] >= 64
          i[0,0] = 0 if ((i.size + 1) + ("%B" % i[0]).size ) > 8
          pad = ("1" * i.size + "0"*6)[0,8].to_i(2)
          RNG_PACK_ERR.call(nil) if i.size >= 7
          r << (i.shift+pad).chr
          r << (i.shift+128).chr while i.size > 0
        end
      }
      offset[0] = ary_index

      return r.force_encoding(Encoding::UTF_8)
    end

    # unpack other
    def unpack_other(cmd, attr, cnt, str, offset)
      case cmd
      when :u, :m
        unpack_uu64(cmd, attr, cnt, str, offset)
      when :M
        unpack_qp(attr, cnt, str, offset)
      when :w
        unpack_ber(attr, cnt, str, offset)
      when :U
        unpack_utf8(attr, cnt, str, offset)
      else
        []
      end
    end

    # pack other
    def pack_other(cmd, attr, cnt, ary, offset)
      case cmd
      when :u, :m
        pack_uu64(cmd, attr, cnt, ary, offset)
      when :M
        pack_qp(attr, cnt, ary, offset)
      when :w
        pack_ber(attr, cnt, ary, offset)
      when :U
        pack_utf8(attr, cnt, ary, offset)
      else
        ""
      end
    end

    #
    # Unpack
    #
    def unpack(str, template)
      r = []
      offset = [0]
      in_comment = false
      template.scan(SCAN).each{|cmd, attr, cnt|
        cmd = cmd.to_sym
        (in_comment = true  ; next ) if cmd == :"#"
        (in_comment = false ; next ) if cmd == :"\n"
        next if in_comment

        ARG_ERR.call(attr) if (attr != "") && !(WITH_ATTR_CMD.include?(cmd))
        RNG_ERR.call(nil) if attr.include?(">") && attr.include?("<")
        ARG_ERR_NOS.call(nil) if cmd == :%

        cnt = (cmd == :"@" ? "0" : "1") if cnt.empty?
        cnt = cnt.to_i if (cnt[0] != "*")

        str = str.b
        case cmd
        when *CMD_ASCII
          r.push(*unpack_ascii(cmd, attr, cnt, str, offset))
        when *CMD_BINHEX
          r.push(*unpack_binhex(cmd, attr, cnt, str, offset))
        when *CMD_INTEGER
          r.push(*unpack_int(cmd, attr, cnt, str, offset))
        when *CMD_FLOAT
          r.push(*unpack_float(cmd, attr, cnt, str, offset))
        when *CMD_MOVE
          unpack_move(cmd, attr, cnt, str, offset)
        when *CMD_OTHER
          r.push(*unpack_other(cmd, attr, cnt, str, offset))
        else
          warn("unknown unpack directive #{cmd}, #{template}", uplevel:2)
        end
      }

      return r
    end

    # Are we really need unpack1?
    def unpack1(str, template)
      offset = [0]
      in_comment = false
      template.scan(SCAN).each{|cmd, attr, cnt|
        cmd = cmd.to_sym
        (in_comment = true  ; next ) if cmd == :"#"
        (in_comment = false ; next ) if cmd == :"\n"
        next if in_comment

        ARG_ERR.call(attr) if (attr != "") && !(WITH_ATTR_CMD.include?(cmd))
        RNG_ERR.call(nil) if attr.include?(">") && attr.include?("<")
        ARG_ERR_NOS.call(nil) if cmd == :%

        cnt = (cmd == :"@" ? "0" : "1") if cnt.empty?
        cnt = cnt.to_i if (cnt[0] != "*")

        str = str.b
        case cmd
        when *CMD_ASCII
          return unpack_ascii(cmd, attr, cnt, str, offset)[0]
        when *CMD_BINHEX
          return unpack_binhex(cmd, attr, cnt, str, offset)[0]
        when *CMD_INTEGER
          return unpack_int(cmd, attr, 1, str, offset)[0]
        when *CMD_FLOAT
          return unpack_float(cmd, attr, 1, str, offset)[0]
        when *CMD_MOVE
          unpack_move(cmd, attr, cnt, str, offset)
        when *CMD_OTHER
          return unpack_other(cmd, attr, cnt, str, offset)[0]
        else
          warn("unknown unpack directive #{cmd}, #{template}", uplevel:2)
        end
      }
    end

    #
    # Pack
    #
    def pack(ary, template)
      r = "".b
      offset = [0]
      template_org = template.dup

      in_comment = false
      template.scan(SCAN).each{|cmd, attr, cnt|
        cmd = cmd.to_sym
        (in_comment = true  ; next ) if cmd == :"#"
        (in_comment = false ; next ) if cmd == :"\n"
        next if in_comment

        ARG_ERR.call(attr) if (attr != "") && !(WITH_ATTR_CMD.include?(cmd))
        ARG_ERR_NOS.call(nil) if cmd == :%

        cnt = "1" if cnt.empty?
        cnt = cnt.to_i if (cnt[0] != "*")
        RNG_ERR_OVR.call(:pack) if cnt.to_i >= 2**64

        case cmd
        when *CMD_ASCII
          r << pack_ascii(cmd, attr, cnt, ary, offset)
        when *CMD_BINHEX
          r << pack_binhex(cmd, attr, cnt, ary, offset)
        when *CMD_INTEGER
          r << pack_int(cmd, attr, cnt, ary, offset)
        when *CMD_FLOAT
          r << pack_float(cmd, attr, cnt, ary, offset)
        when *CMD_MOVE
          pack_move(cmd, attr, cnt, r)
        when *CMD_OTHER
          r << pack_other(cmd, attr, cnt, ary, offset)
        else
          warn("unknown pack directive #{cmd}, #{template}", uplevel:2)
        end
        RUN_CHG_ERR.call(nil) if template_org != template
      }
      return r
    end

  end

end

class Array

  alias :orig_pack :pack if Array.method_defined?(:pack)

  def pack(template)
    PurePack.pack(self, template)
  end

end

class String

  alias :orig_unpack :unpack if String.method_defined?(:unpack)

  def unpack(template)
    if block_given?
      PurePack.unpack(self, template).each {|n|
        next unless n
        yield n
      }
      nil
    else
      PurePack.unpack(self, template)
    end
  end

  def unpack1(template)
    PurePack.unpack1(self, template)
  end

end
