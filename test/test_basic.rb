require_relative 'helper'

class TestTest1 < Test::Unit::TestCase

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
    socket.send("\x05\x00\x00", 4)
    ret = socket.read(2)
    assert_equal ret[0], "\x05"
    assert_equal ret[1], "\x00"
    killall
  end
end
