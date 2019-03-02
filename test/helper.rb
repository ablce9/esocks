require 'socket'
require 'test/unit'

$VERBOSE = true

ESOCKS = '../esocks'

module Helper

  SIGNAL = 'TERM'

  attr_reader :pids

  def setup
    check_esocks
    @pids ||= []
  end

  def run_server(*server_args)
    pid = spawn(ESOCKS, *server_args)
    add_pid(pid)
    Signal.trap('TERM') { |sig| Process.kill(sig, pid) }
    Process.detach(pid)
    pid
  end

  def kill_process(pid, sig = SIGNAL)
    Process.kill(sig, pid)
    remove_pid(pid)
  end

  def killall
    pids.each do |pid|
      Process.kill(SIGNAL, pid)
    end
  rescue Errno::ESRCH => e
    puts e
  end

  def remove_pid(pid)
    @pids.delete(pid)
  end

  def add_pid(pid)
    @pids << pid
  end

  def check_esocks
    unless File.exist?(ESOCKS)
      raise
    end
  end

  module Client
    include Helper

    def create_socks_client(host, port)
      socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      addr = Socket.sockaddr_in(port, host)
      begin
        socket.connect_nonblock(addr)
      rescue Errno::EINPROGRESS
      end
      socket # .send(0x5, 0x01, 0x00, 3)
    end

    def send(socket, msg, &block) # int
      begin
        ret = socket.sendmsg_nonblock(msg)
        yield ret
      rescue IO::WaitWritable
        IO.select([socket])
        retry
      end
    end

    def read(socket, len, &block) # buf
      begin
        ret = socket.recvmsg_nonblock(len)[0]
        yield ret
      rescue IO::WaitReadable
        IO.select([socket])
        retry
      end
    end

    def byte_to_short(n)
      [n >> 8, n&0x0ff].map(&:chr).join
    end
  end
end
