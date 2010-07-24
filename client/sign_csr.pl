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
                                     'password'    => $ENV{'LOKI_PASSWD'},
                                   }
                  );
$mech->get($uri."/");

if(grep "<legend>Valid Certificate Found.</legend> ", $mech->content){
    print "valid cert found. Revoking\n";
    $mech->click_button( 'name' => 'revoke' );
}
