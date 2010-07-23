#!/usr/bin/perl
use WWW::Mechanize;
use Data::Dumper;
use JSON;
my $uri="https://loki.websages.com";
my $mech = WWW::Mechanize->new();
$mech->get( $uri );
$mech->submit_form(
                    fields      => {
                                     'username'    => 'loki',
                                     'password'    => 'eocMgOmociSoDPjO',
                                   }
                  );
$mech->get($uri."/jstree");
print $mech->content;
