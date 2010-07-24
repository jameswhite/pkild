#!/usr/bin/perl
use WWW::Mechanize;
my $uri="https://loki.websages.com";
my $mech = WWW::Mechanize->new();
my $successful_creation=0;
my $count=0;
while( ($successful_creation==0) && ($count < 6) ){
    $mech->get( $uri );
    # find the legends on the page to determine which form we're seeing
    my @legends = grep(/<legend>.*<\/legend>/, split('\n',$mech->content)); 
    for(my $idx=0; $idx<=$#legends; $idx++){
        $legends[$idx]=~s/.*<legend>//;
        $legends[$idx]=~s/<\/legend>.*//;
    }
    # if there is a certificate, then we want to revoke it (or why are we running?)
    if(grep /Valid Certificate Found/, @legends){
        print "valid cert found. Revoking\n";
        $mech->click_button( 'name' => 'revoke' );
    # if there not a certificate, then we want to create one.
    }elsif(grep /Certficate Signing Request/, @legends){
        print "no cert found. creating a certificate signing request and posting for signature\n";
        # make our tmp dir
        # make our key
        # get our openssl.cnf
        $mech->follow_link( 'text' => 'OpenSSL config for batch CSR creation' );
        print $mech->content."\n";
        $mech->back();
        # create our CSR 
        # post our CSR
        $mech->submit_form(
                            with_fields => {
                                             'csr_request'    => 'oh, hai.',
                                           }
                          );
        # Retrieve our cert
        # install our cert
        # validate our cert
        $successful_creation=1;
    }elsif(grep /Please [Ll]og [Ii]n/, @legends){
        print "We need to Authenticate.\n";
        $mech->submit_form(
                            with_fields => {
                                             'username'    => 'loki',
                                             'password'    => $ENV{'LOKI_PASSWD'},
                                           }
                          );
    }else{
        print "Unhandled legends found:\n";
        print join('\n',@legends)."\n";
    }
    $count++;
}
