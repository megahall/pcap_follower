#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket;
use Time::HiRes qw(sleep usleep);

# 1024 bytes - 20 byte IP header - 8 byte UDP header = 996
my $size = 996;
my $buffer = "CRAP" x (996 / 4);

my $blackhole = IO::Socket::INET->new('Proto' => 'udp', 'LocalAddr' => '127.0.0.1', 'LocalPort' => 10000);
my $socket = IO::Socket::INET->new('Proto' => 'udp', 'PeerAddr' => '127.0.0.1', 'PeerPort' => 10000);

while (1) {
    $socket->send($buffer);
    # usleep(50);
}

exit(0);
