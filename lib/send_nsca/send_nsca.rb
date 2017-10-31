module SendNsca

  STATUS_OK = 0
  STATUS_WARNING = 1
  STATUS_CRITICAL = 2
  STATUS_UNKNOWN = 3

  NONE = 0
  XOR = 1

  class NscaConnection

    require 'socket'      # Sockets are in standard library

    # todo: replace timeout with a better method of handling communication timeouts. (nonblocking sockets and IO.select ?)
    require 'timeout'
    require 'zlib'
    require 'mcrypt'
    attr_accessor :nscatimeout

    # params for connecting to the nsca/nagios server
    attr_accessor  :nscahost
    attr_accessor  :port

    # connection status and error if one found
    attr_reader   :connected
    attr_reader   :error

    # read from the nsca/nagios server
    attr_accessor  :iv_and_timestamp

    # converted from :iv_and_timestamp
    attr_accessor  :iv_and_timestamp_str
    attr_accessor  :iv_string
    attr_accessor  :iv
    attr_accessor  :timestring
    attr_accessor  :timestamp_hex
    attr_accessor  :timestamp

    # encryption_mode
    attr_accessor  :encryption_mode
    attr_accessor  :password

    # status data to send to nagios
    # :hostname, :return_code and :status are required parameters
    # To send hostcheck omit :service
    attr_accessor  :hostname
    attr_accessor  :service
    attr_accessor  :return_code
    attr_accessor  :status

    # debug
    attr_accessor :debug

    # for sending to nsca
    attr_accessor  :crc
    PACKET_VERSION = 3
    INITIAL_PACKET_LEN = 132
    DEFAULT_TIMEOUT = 1
    PACK_STRING = "nxx N a4 n a64 a128 a512xx"

    # MCRYPT parameters (need more algorithms: figure out iv/key sizes)
    @@MCRYPT_PARAMS = {
      3  => {:algorithm => 'tripledes',    :key_size => 24, :iv_size => 8},
      8  => {:algorithm => 'blowfish',     :key_size => 56, :iv_size => 8},
      14 => {:algorithm => 'rijndael-128', :key_size => 32, :iv_size => 16},
      15 => {:algorithm => 'rijndael-192', :key_size => 32, :iv_size => 24},
      16 => {:algorithm => 'rijndael-256', :key_size => 32, :iv_size => 32},
    }

    def initialize(args)
      # connecting to nagios
      @nscahost = args[:nscahost]
      @port = args[:port]
      @hostname = args[:hostname]
      @service = args[:service]
      @return_code = args[:return_code]
      @status = args[:status]
      @connected = false
      @password = args[:password] || ''
      @timeout = args[:nscatimeout] || DEFAULT_TIMEOUT
      @encryption_mode = args[:encryption_mode] || SendNsca::XOR
      @debug = args[:debug] || false
    end

    def connect_and_get_iv
      begin
        Timeout.timeout(@timeout) do # the server has @timeout second(s) to answer
          @tcp_client = TCPSocket.open(@nscahost, @port)
          @connected = true
          @iv_and_timestamp = @tcp_client.recv(INITIAL_PACKET_LEN)
          if @iv_and_timestamp.size != INITIAL_PACKET_LEN then
            raise "can't read initial packet from server"
          end
      end
      rescue
        @connected = false
        @error = "send_ncsa - error connecting to nsca/nagios: #{$!}"
        puts @error
        @tcp_client.try(:close) unless @tcp_client.nil?
        raise # re-raise same exception
      end
      timestamp_for_logging
    end

    def convert_timestamp
      # convert timestamp for use in comm to nagios
      @timestring = @iv_and_timestamp[@iv_and_timestamp.length-4,@iv_and_timestamp.length]
    end

    def timestamp_for_logging
      # convert timestamp in a format we can log
      @iv_and_timestamp_str = @iv_and_timestamp.unpack("H*")
      @timestring_for_log = @iv_and_timestamp_str[0][256,8]
      @timestamp_hex = @timestring_for_log.hex
      @timestamp = Time.at(@timestamp_hex)
    end

    def convert_iv
      # strip off the last 4 characters which are the timestamp
      @iv = @iv_and_timestamp[0,@iv_and_timestamp.length-4]
    end

    def intialize_nsca_connection
      connect_and_get_iv
      convert_timestamp
      convert_iv
    end

    def send_nsca
      intialize_nsca_connection
      @crc = 0
      nsca_params = [PACKET_VERSION, @crc, @timestring, @return_code, @hostname, @service, @status ]
      string_to_send_without_crc = nsca_params.pack(PACK_STRING)

      @crc = Zlib::crc32(string_to_send_without_crc)
      nsca_params = [PACKET_VERSION, @crc, @timestring, @return_code, @hostname, @service, @status ]
      string_to_send_with_crc = nsca_params.pack(PACK_STRING)

      if @debug
        puts %{DEBUG: PACKET_VERSION = #{PACKET_VERSION}
@crc = #{@crc}
@timestring = #{@timestring}
@timestamp_hex = #{Time.at(timestamp_hex)}
@return_code #{@return_code}
@hostname = #{@hostname}
@service = #{@service}
@status = #{@status}}
        puts "string_to_send_with_crc = #{string_to_send_with_crc.length}"
        puts "string_to_send_with_crc = #{string_to_send_with_crc.unpack('H*')}"
      end

      if @encryption_mode == SendNsca::NONE
        string_to_send = string_to_send_with_crc
      else
        if @encryption_mode == SendNsca::XOR
          string_to_send = SendNsca::NscaConnection.xor(@iv, string_to_send_with_crc, @password)
        elsif @@MCRYPT_PARAMS[@encryption_mode]
          string_to_send = SendNsca::NscaConnection.encrypt(@iv, string_to_send_with_crc, @password, @@MCRYPT_PARAMS[@encryption_mode])
        else
          raise "unsupported encryption mode: #{@encryption_mode.tos}"
        end
        if @debug
          puts "encrypted_string_to_send = #{string_to_send.length}"
          puts "encrypted_string_to_send = #{string_to_send.unpack('H*')}"
        end
      end

      @tcp_client.send(string_to_send, 0)
      @tcp_client.close
      @connected = false
    end

    def self.xor(iv, str, password='')

      str_a = str.unpack("C*")
      iv_a = iv.unpack("C*")
      password_a = password.unpack("C*")
      result = []

      str_a.each_with_index do |c, i|
        result[i] = c ^ iv_a[i % iv_a.size]
        result[i] ^= password_a[i % password_a.size] unless password_a.empty?
      end

      return result.pack("C*")
    end

    def self.encrypt(iv, str, password, mcrypt_params)
      key = ''
      if password.length < mcrypt_params[:key_size]
        key = "\0" * mcrypt_params[:key_size]
        key[0,password.length] = password
      elsif password.length > mcrypt_params[:key_size]
        key = password[0,mcrypt_params[:key_size]]
      else
        key = password
      end
      crypto = Mcrypt.new(mcrypt_params[:algorithm], :cfb, key, iv[0,mcrypt_params[:iv_size]], false)
      return crypto.encrypt(str)
    end

  end

end

