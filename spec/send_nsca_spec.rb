require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

include SendNsca
require 'zlib'

describe "SendNsca" do

  before(:each) do
    # do something here if needed
  end

  it "should create a valid crc" do 
    
    #    Hello crc = 4157704578
    hello = "Hello"
    crc_hello = Zlib::crc32(hello)
    crc_hello.should eql 4157704578
    
    #    world! crc = 2459426729
    world = " world!"
    hello_world_1 = Zlib::crc32(world)
    hello_world_1.should eql 2459426729
    
    #    Hello World crc = 1243066710
    hello_world = "Hello World"
    hello_world_2 = Zlib::crc32(hello_world)
    hello_world_2.should eql 1243066710
  end

  it "should perform valid xor encryption that can be deencrypted" do 
  
    iv = "\377\376\375"
    str = "Hello!"
    encrypted_str = SendNsca::NscaConnection.xor(iv,str)
    deencrypted_str = SendNsca::NscaConnection.xor(iv,encrypted_str)
    deencrypted_str.should eql str

    iv = "adsfkahudsflihasdflkahdsfoaiudfh-3284rqiuy8rtq49087ty  2-\123\666\001\004\377"
    str = "Hey There This is awesome!!!\000!"
    encrypted_str = SendNsca::NscaConnection.xor(iv,str)
    deencrypted_str = SendNsca::NscaConnection.xor(iv,encrypted_str)
    deencrypted_str.should eql str
    
    str = "\000\000\000\000\x1\x2\x3_abc123&*#"
    encrypted_str = SendNsca::NscaConnection.xor(iv,str)
    deencrypted_str = SendNsca::NscaConnection.xor(iv,encrypted_str)
    deencrypted_str.should eql str
  end
  
  it "should perform valid xor encryption that can be deencrypted and accept a password" do 
  
    iv = "\377\376\375"
    str = "Hello!"
    encrypted_str = SendNsca::NscaConnection.xor(iv,str, "YOURPASSWORD")
    deencrypted_str = SendNsca::NscaConnection.xor(iv,encrypted_str, "YOURPASSWORD")
    deencrypted_str.should eql str

    iv = "adsfkahudsflihasdflkahdsfoaiudfh-3284rqiuy8rtq49087ty  2-\123\666\001\004\377"
    str = "Hey There This is awesome!!!\000!"
    encrypted_str = SendNsca::NscaConnection.xor(iv,str, "YOURPASSWORD")
    deencrypted_str = SendNsca::NscaConnection.xor(iv,encrypted_str, "YOURPASSWORD")
    deencrypted_str.should eql str
    
    str = "\000\000\000\000\x1\x2\x3_abc123&*#"
    encrypted_str = SendNsca::NscaConnection.xor(iv, str, "YOURPASSWORD")
    deencrypted_str = SendNsca::NscaConnection.xor(iv, encrypted_str, "YOURPASSWORD")
    deencrypted_str.should eql str
  end

  it 'should correctly convert iv and timestamp' do
    iv_ts = "\x60\x4f\xba\x60\xaf\x1f\x6b\xa0\xd0\xa8\xf0\x4c\x54\x46\x33".force_encoding('BINARY')+
"\x03\x67\xad\xd4\x43\x8f\x07\xd2\xfd\xec\x98\xc0\x4a\x3f\xfb".force_encoding('BINARY')+
"\xa9\x9f\x4b\x64\xff\xfa\x84\x6b\x9a\x54\x14\x8b\xa0\x68\xd1".force_encoding('BINARY')+
"\xd3\x6b\x39\x81\x40\x7c\x10\x47\x4e\x0e\x34\xe7\xce\x7e\x26".force_encoding('BINARY')+
"\xca\x28\xc6\x15\x8d\xc6\x10\x11\x32\xab\x65\x46\x36\x06\xaf".force_encoding('BINARY')+
"\x08\xd9\x1a\x41\x5b\x5a\xbe\x6c\xa2\x0d\x7a\xd6\xf5\x49\x55".force_encoding('BINARY')+
"\x1c\x13\x7e\xe2\x29\x0b\xa9\x39\x1c\xdc\xe5\x82\x22\x1c\x88".force_encoding('BINARY')+
"\xd1\x24\x62\xec\x66\xbd\x47\x25\x2a\xe9\x32\xa4\xc0\x27\xee".force_encoding('BINARY')+
"\x15\x44\x01\x94\x27\x2b\x9f\xd0\x56\xdb\xef\x1e".force_encoding('BINARY')

    ts = "\x56\xdb\xef\x1e".force_encoding('BINARY')
    client = SendNsca::NscaConnection.new({})
    client.instance_variable_set(:@iv_and_timestamp, iv_ts)
    client.timestamp_for_logging
    client.convert_timestamp
    client.convert_iv
    Zlib::crc32(client.iv).should eql 2201516811
    Zlib::adler32(client.iv).should eql 1209023010

    client.iv.should eql iv_ts[0,iv_ts.length-4]

    Zlib::crc32(client.timestring).should eql 1830258675
    Zlib::adler32(client.timestring).should eql 99156543
    client.timestring.should eql ts
  end

  it 'should correctly encrypt data with mcrypt' do
    iv_ts = "\x60\x4f\xba\x60\xaf\x1f\x6b\xa0\xd0\xa8\xf0\x4c\x54\x46\x33".force_encoding('BINARY')+
"\x03\x67\xad\xd4\x43\x8f\x07\xd2\xfd\xec\x98\xc0\x4a\x3f\xfb".force_encoding('BINARY')+
"\xa9\x9f\x4b\x64\xff\xfa\x84\x6b\x9a\x54\x14\x8b\xa0\x68\xd1".force_encoding('BINARY')+
"\xd3\x6b\x39\x81\x40\x7c\x10\x47\x4e\x0e\x34\xe7\xce\x7e\x26".force_encoding('BINARY')+
"\xca\x28\xc6\x15\x8d\xc6\x10\x11\x32\xab\x65\x46\x36\x06\xaf".force_encoding('BINARY')+
"\x08\xd9\x1a\x41\x5b\x5a\xbe\x6c\xa2\x0d\x7a\xd6\xf5\x49\x55".force_encoding('BINARY')+
"\x1c\x13\x7e\xe2\x29\x0b\xa9\x39\x1c\xdc\xe5\x82\x22\x1c\x88".force_encoding('BINARY')+
"\xd1\x24\x62\xec\x66\xbd\x47\x25\x2a\xe9\x32\xa4\xc0\x27\xee".force_encoding('BINARY')+
"\x15\x44\x01\x94\x27\x2b\x9f\xd0\x56\xdb\xef\x1e".force_encoding('BINARY')

    args = {
      :nscahost => '127.0.0.1',
      :port => 5667,
      :hostname => 'myhostname.example.org',
      :service => 'servicename',
      :password => 'simply_qwerty1234',
      :encryption_mode => 8, # blowfish
      :return_code => 2,
      :status => 'some status message',
    }
    client = SendNsca::NscaConnection.new(args)
    client.instance_variable_set(:@iv_and_timestamp, iv_ts)
    client.timestamp_for_logging
    client.convert_timestamp
    client.convert_iv

    # this is from send_nsca
    crc = 0
    nsca_params = [SendNsca::NscaConnection::PACKET_VERSION, crc, client.timestring, client.return_code, client.hostname, client.service, client.status ]
    str_no_crc = nsca_params.pack(SendNsca::NscaConnection::PACK_STRING)
    crc = Zlib::crc32(str_no_crc)
    nsca_params = [SendNsca::NscaConnection::PACKET_VERSION, crc, client.timestring, client.return_code, client.hostname, client.service, client.status ]
    str_crc = nsca_params.pack(SendNsca::NscaConnection::PACK_STRING)

    Zlib::crc32(str_crc).should eql 2553349791
    Zlib::adler32(str_crc).should eql 4079884668

    mcrypt_params = SendNsca::NscaConnection.class_variable_get(:@@MCRYPT_PARAMS)
    enc_str = SendNsca::NscaConnection.encrypt(client.iv, str_crc, client.password, mcrypt_params[client.encryption_mode])

    Zlib::crc32(enc_str).should eql 553693238
    Zlib::adler32(enc_str).should eql 1403937026

    client.password = 'short_and_sweet'
    client.encryption_mode = 3 # 3des
    enc_str2 = SendNsca::NscaConnection.encrypt(client.iv, str_crc, client.password, mcrypt_params[client.encryption_mode])

    Zlib::crc32(enc_str2).should eql 3750005222
    Zlib::adler32(enc_str2).should eql 1692756456

    client.encryption_mode = 14 # RIJNDAEL-128
    client.password = 'long_and_boring_password.................................................................12345678'
    enc_str3 = SendNsca::NscaConnection.encrypt(client.iv, str_crc, client.password, mcrypt_params[client.encryption_mode])

    Zlib::crc32(enc_str3).should eql 2369692810
    Zlib::adler32(enc_str3).should eql 3359335401
  end

  it "should correctly send a message to the server" do

    args = {
      :nscahost => "192.168.1.216", # maybe this should default to 127.0.0.1, and/or use ENV['nscahost]
      :port => 5667,
      :hostname => "kbedell",
      :service => "passive-checkin-test01" ,
      :return_code => SendNsca::STATUS_OK,
      :status => "TEST"
    }
    nsca_connection = SendNsca::NscaConnection.new(args)

    nsca_connection.send_nsca

  end

end

