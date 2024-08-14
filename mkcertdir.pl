#!/usr/bin/env perl

use strict;
use warnings;
use autodie qw(open chdir symlink);
use feature qw(say);

our $CACERT      = "ca-bundle.crt";
our $CACERT_URL  = "https://curl.se/ca/cacert.pem";
our $CURL_CMD    = "/usr/bin/curl";
our $OPENSSL_CMD = "/usr/bin/openssl";
our $CERT_EXT    = ".pem";

my $name;
my $start = 0;
my @lines;


sub download_cacert {

	my @command = ($CURL_CMD, "-sSL", "-o", $CACERT, $CACERT_URL);
	system @command;
	my $exit_code = $? >> 8;
	die "curl exit_code:$exit_code" if $exit_code != 0;
	#my $req = HTTP::Request->new(GET => $CACERT_URL);
	#my $ua = LWP::UserAgent->new;
	#my $res = $ua->request($req);
	#if ($res->is_success) {
	#	open my $fh, ">", $CACERT;
	#	say $fh $res->content;
	#	close $fh;
	#} else {
	#	die $res->status_line;
	#}
}

sub make_cert {

	my ($name, $ref) = @_;
	$name =~ s/ /_/g;
	my $fname = "${name}${CERT_EXT}";
	open my $fh, ">", $fname;
	say $fh join("\n", @$ref);
	close $fh;
	return $fname;
}

sub make_hash_name {

	my $name = shift;
	my $num = 0;
	my $hash_name;
	my @command = ($OPENSSL_CMD, "x509", "-hash", "-noout", "-in", $name);
	open my $child, "-|", @command;
	chomp(my $hash = <$child>);
	close $child;
	while (1) {
		$hash_name = "${hash}.${num}";
		if (-l $hash_name) {
			$num++;
		} else {
			last;
		}
	}
	return $hash_name;
}

my $dir = @ARGV[0];
chdir $dir if $dir;

download_cacert();

open my $fh, "<", $CACERT;
while (my $line = <$fh>) {

	$line =~ s/[\r\n]+//g;
	if (!$name && $line =~ /^[A-za-z0-9]+/) {
		$name = $line;
		next;
	}
	
	if ($line =~ /^===+/) {
		next;
	}

	if ($line eq "-----BEGIN CERTIFICATE-----") {
		push @lines, $line;
		$start = 1;
		next;
	}
	if ($start == 1 && $line ne "-----END CERTIFICATE-----") {
		push @lines, $line;
		next;
	}
	if ($line eq "-----END CERTIFICATE-----") {
		push @lines, $line;

		my $fname     = make_cert($name, \@lines);
		my $hash_name = make_hash_name($fname);
		symlink $fname, $hash_name;
		say "symlink created: $hash_name -> $fname";
		$start = 0;
		$name  = undef;
		@lines = ();
	}
}
close $fh;
