#! /usr/bin/perl

use strict;
# Silence annoying warnings about non-portable 64-bit hex(); alternative is to use Math::BigInt
#use warnings;

my $mmap;

sub load_mapping {
  my ($pid)= @_;

  open F, '<', "/proc/$pid/maps"
      or die "Failed to open /proc/$pid/maps: $!\n";

  my $arr= [];
  while (<F>) {
    next unless m|^([a-f0-9]+)-([a-f0-9]+) ..x. ([a-f0-9]+) [0-9:]+ [0-9]+ +(/.*)|;
    push @$arr, { S => hex($1), E => hex($2), B => hex($3), F => $4 };
  }
  close F;
  sort { $a->{S} <=> $b->{S} } @$arr;
  $mmap= $arr;
}

my $syms= { };

sub resolve_addr {
  my ($addr)= @_;

  for my $e (@$mmap) {
    next if $e->{E} <= $addr;
    last if $e->{S} > $addr;

    # Found, look up.
    my $image= $e->{F};
    my $start= $e->{S};
    my $base= $e->{B};

    # The address 0x400000 seems to be magic, so that symbols in main
    # executable binary are already relocated wrt. this load address.
    my $rel_addr= $addr - ($start == 0x400000 ? 0 : $start) + $base;

    # Load symbol table if not loaded already.
    if (!exists($syms->{$image})) {
      die if $image =~ /\'/;
      my $cmd;
      if ($image !~ /\.so/) {
        $cmd= "nm --demangle --numeric-sort --defined-only '$image'";
      } else {
        my $dbg_image= $image;
        $dbg_image =~ s!^(/lib/|/usr/lib/)!/usr/lib/debug/!;
        if (-e $dbg_image) {
          $cmd= "nm --demangle --numeric-sort --defined-only '$dbg_image'";
        } else {
          $cmd= "nm --dynamic --demangle --numeric-sort --defined-only '$image'";
        }
      }

      open P, "$cmd |"
          or die "open(): $!";
      my $arr= [];
      while (<P>) {
        next unless /^([a-f0-9]+) [a-zA-Z] (.*)/;
        push @$arr, [hex($1), $2];
      }
      close P;
      $syms->{$image}= $arr;
    }

    # Now look up the address using binary search.
    my $s= $syms->{$image};

    my $low= 0;
    my $high= @$s;
    for (;;) {
      my $mid= int(($low+$high)/2);
      last unless $mid > $low;
      if ($s->[$mid][0] > $rel_addr) {
        $high= $mid;
      } else {
        $low= $mid;
      }
    }
    my $func_start= $s->[$low][0];
    my $func_name= $s->[$low][1];
    my $func_into= $rel_addr - $func_start;
    return "<$func_name+$func_into> ($image)";
  }

  return sprintf("0x%x", $addr);
}

die "Usage: $0 <pid>"
    unless @ARGV == 1;

my $pid= $ARGV[0];
load_mapping($pid);

for (@$mmap) {
  printf "0x%x - 0x%x (0x%x): %s\n", $_->{S}, $_->{E}, $_->{B}, $_->{F};
}

#open PIP, "./get_stacktrace $pid |" or die "open(): $!";
open PIP, "<&STDIN" or die "open(): $!";
# Get the whole thing as fast as possible, slow processing only after.
my @lines= <PIP>;
close(PIP);

for my $line (@lines) {
  if ($line =~ /^ip = ([a-f0-9]+) <>\+0$/) {
    print resolve_addr(hex($1)), "\n";
  } else {
    print $line;
  }
}
