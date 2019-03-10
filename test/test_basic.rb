require 'ipaddr'
require_relative 'helper'

IPV4_ADDR = IPAddr.new('172.217.31.142') # google.com
HTTP_PORT = 80

class Test1 < Test::Unit::TestCase

  include Helper::Client

  def test_run_with_args
    pid = run_server('-p', '2020', '-k', 'password', '-P', './pids/1.pid')
    assert_equal pids.include?(pid), true
    kill_process(pid)
  end

  def test_cli_and_srv
    run_server('-p', '2021', '-k', 'password', '-P', './pids/1.pid')
    run_server('-p', '2020', '-s', '127.0.0.1', '-j', '2021', '-k', 'password', '-P', './pids/2.pid') # client
    sleep 1
    socket = create_socks_client('127.0.0.1', 2020)
    send(socket, "\x05\x00\x00") do |num|
      assert_equal num, 3
    end
    read(socket, 2) do |buf|
      assert_equal buf[0].unpack('C')[0], 5
      assert_equal buf[1].unpack('C')[0], 0
    end
    send(
      socket,
      "\x05\x01\x00\x01" +
      IPV4_ADDR.hton +
      byte_to_short(HTTP_PORT)) do |num|
      assert_equal num, 10
    end
    read(socket, 2) do |buf|
      assert_equal buf[0].unpack('C')[0], 5
      assert_equal buf[1].unpack('C')[0], 0
    end
    send(socket, "GET /\n\n") do |num|
      assert_equal num, 7
    end
    killall
  end

  def test_cli_2
    run_server('-p', '2022', '-k', 'password', '-P', './pids/1.pid')
    run_server('-p', '2023', '-s', '127.0.0.1', '-j', '2022', '-k', 'password', '-P', './pids/2.pid') # client
    sleep 1
    socket = create_socks_client('127.0.0.1', 2023)
    send(socket, "\x05\x00\x00") do |num|
      assert_equal num, 3
    end
    read(socket, 2) do |buf|
      assert_equal buf[0].unpack('C')[0], 5
      assert_equal buf[1].unpack('C')[0], 0
    end
    send(
      socket,
      "\x05\x02\x00\x03" + "\xa" + "google.com" + byte_to_short(HTTP_PORT)) do |num|
      assert_equal num, 17
    end
    read(socket, 2) do |buf|
      assert_equal buf[0].unpack('C')[0], 5
      assert_equal buf[1].unpack('C')[0], 0
    end
    send(socket, "GET /\n\n") do |num|
      assert_equal num, 7
    end
    killall
  end
end
