require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

include SendNsca

describe "SendNsca" do

  before(:each) do
    # do something here if needed
  end

  it "should create a valid crc" do 
    
    #    Hello crc = 4157704578
    hello = "Hello"
    crc_hello = SendNsca::NscaConnection.crc32(hello)
    crc_hello.should eql 4157704578
    
    #    world! crc = 2459426729
    world = " world!"
    hello_world_1 = SendNsca::NscaConnection.crc32(world)
    hello_world_1.should eql 2459426729
    
    #    Hello World crc = 1243066710
    hello_world = "Hello World"
    hello_world_2 = SendNsca::NscaConnection.crc32(hello_world)
    hello_world_2.should eql 1243066710
  end

  it "should perform valid xor encryption that can be deencrypted" do 
  
    xor_key = "\377\376\375"
    str = "Hello!"
    encrypted_str = SendNsca::NscaConnection.xor(xor_key,str)
    deencrypted_str = SendNsca::NscaConnection.xor(xor_key,encrypted_str)
    deencrypted_str.should eql str

    xor_key = "adsfkahudsflihasdflkahdsfoaiudfh-3284rqiuy8rtq49087ty  2-\123\666\001\004\377"
    str = "Hey There This is awesome!!!\000!"
    encrypted_str = SendNsca::NscaConnection.xor(xor_key,str)
    deencrypted_str = SendNsca::NscaConnection.xor(xor_key,encrypted_str)
    deencrypted_str.should eql str
    
    str = "\000\000\000\000\111\222\333\123\321"
    encrypted_str = SendNsca::NscaConnection.xor(xor_key,str)
    deencrypted_str = SendNsca::NscaConnection.xor(xor_key,encrypted_str)
    deencrypted_str.should eql str

    str = "\000\000\000\000\111\222\333\123\321"
    encrypted_str = SendNsca::NscaConnection.xor(xor_key, str, "YOURPASSWORD")
    deencrypted_str = SendNsca::NscaConnection.xor(xor_key, encrypted_str, "YOURPASSWORD")
    deencrypted_str.should eql str
  end
  
  it "should correctly send a message to the server" do 
    
    args = {
      :nscahost => "192.168.1.216",
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

