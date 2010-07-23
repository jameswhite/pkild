#!/usr/bin/perl
use WWW::Mechanize;
use Data::Dumper;
my $mech = WWW::Mechanize->new();
$mech->get( "https://eir.websages.com/" );
$mech->submit_form(
                    fields      => {
                                     'username'    => 'loki',
                                     'password'    => 'PSEbJQnNHdPNhQPe',
                                   }
                  );

$mech->get("https://eir.websages.com/jstree");
print $mech->content;
