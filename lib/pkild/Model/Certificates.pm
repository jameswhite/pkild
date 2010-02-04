package pkild::Model::Certificates;

use strict;
use base 'Catalyst::Model::File';

__PACKAGE__->config(
    root_dir => '/var/tmp/certificate_authority',
);

################################################################################
# Return a list of hashes of lists of hashes that describe the directory tree
################################################################################
sub tree{
    my ($self, $c)=@_;
    my $tree;
    my $node_separator="::";
    my @file_names=$self->list(mode => 'both', recurse =>1);
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    $rootdir=~s/^\///;
    @file_names=sort(@file_names);
    my $previous_node='';
    my $type;
    for my $node (@file_names){
        next if $node eq '.';
        # skip directories containing key data
        next if $node=~m/_data$/;
        # We need to know if this is a file, or a directory
        $type="unknown";
        if( -d $node){ $type="folder"; }
        if( -f $node){ $type="file"; }
        $node=~s/$rootdir//g;
        $node=~s/^\///g;
        if(! defined $tree->{$node}){  
            my @nodeparts=split("\/",$node);
            $node=~s/\//$node_separator/g;
            $tree->{$node} = { 
                               'attributes' => { 'id' => $node, 'rel' => $type },
                               'data'       => $nodeparts[$#nodeparts],
                             };
            pop(@nodeparts);
            my $updir=join("$node_separator",@nodeparts);
            if(!defined( $tree->{ $updir }->{'children'} )){
               push( @{ $tree->{ $updir }->{'children'} }, $node );
            }else{
               my $found=0;
               foreach my $child (@{ $tree->{ $updir }->{'children'} }){
                   if($node eq $child){ $found=1;}
               }
               if(! $found){ push( @{ $tree->{ $updir }->{'children'} }, $node ); }
           }
        }
    }
    # now dereference the children to their actual structs.
    foreach my $key (reverse(sort(keys(%{ $tree })))){
        if(defined( $tree->{$key}->{'children'} && $key ne '')){
            for(my $childidx=0; $childidx<=$#{$tree->{$key}->{'children'} }; $childidx++){ 
                if(defined( $tree->{$key}->{'children'}->[$childidx] )){
                    $tree->{$key}->{'children'}->[$childidx] = YAML::Load(YAML::Dump($tree->{ $tree->{$key}->{'children'}->[$childidx] }));
                }else{
                    $tree->{$key}->{'children'}->[$childidx] = undef;
                }
            }
        }
    }
    return $tree->{''}->{'children'};
}

sub ca_create{
    use FileHandle;
    use Template;
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my $template=Template->new();
    $rootdir=~s/^\///;
    my $tpldata;
    if($param->{'ca-domain'}){
        if( ! -d "$rootdir/$param->{'ca-domain'}" ){
            umask(0077);
            mkdir("$rootdir/$param->{'ca-domain'}",0700); 
            foreach my $key (keys(%{ $param } )){
                $tpldata->{$key} = $param->{$key};
            }
            foreach my $prefs (@{ $session->{'menudata'}->{'openssl_cnf_prefs'}->{'fields'} }){
                $tpldata->{$prefs->{'name'}} = $prefs->{'value'};
            }
            my $text=$self->openssl_cnf_template(); 
            $template->process(\$text,$prefs,"$rootdir/$param->{'ca-domain'}/openssl.cnf")
            my $fh = FileHandle->new("> $rootdir/$param->{'ca-domain'}/$param->{'ca-domain'}.crt");
            if (defined $fh) {
               print $fh Data::Dumper->Dump([$tpldata]);
               print $fh $self->openssl_cnf_template();
               $fh->close;
               return "SUCCESS";
            }
            chmod(0700, "$rootdir/$param->{'ca-domain'}/$param->{'ca-domain'}.crt");
        }
    }
    return "ERROR";
}

sub node_type{
    my ($self, $node)=@_;
    #
    return undef;
}

sub openssl_cnf_template{
    my ($self)=shift;
    my $the_template = <<_END_TEMPLATE_;
HOME = [% PKILD_CERTIFICATE_ROOT %]
RANDFILE = \$ENV::HOME/.rnd
DOMAIN = [% DOMAIN %]
 
[ ca ]
default_ca = CA_default # The default ca section
[ CA_default ]
dir = .
certs = \$dir/certs
crl_dir = \$dir/crl
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/~LEVEL~.[% DOMAIN %].pem
serial = \$dir/serial
crlnumber = \$dir/crlnumber
crl = \$dir/crl.[% DOMAIN %].pem
private_key = \$dir/private/~LEVEL~.[% DOMAIN %].key
RANDFILE = \$dir/private/.rand
x509_extensions = usr_cert
name_opt = ca_default
cert_opt = ca_default
default_days = [% LIFETIME_DAYS %]
default_crl_days= [% CRL_EXPIRE %]
default_md = sha1
preserve = no
policy = policy_match
 
[ policy_match ]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
 
[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
 
[ req ]
default_bits = 1024
default_keyfile = [% DOMAIN %].pem
distinguished_name = req_distinguished_name
attributes = req_attributes
x509_extensions = v3_ca
 
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
countryName_default = [% CA_COUNTRY %]
countryName_min = 2
countryName_max = 2
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default = [% CA_STATE %]
localityName = Locality Name (eg, city)
localityName_default = [% CA_LOCALITY %]
0.organizationName = Organization Name (eg, company)
0.organizationName_default = [% CA_ORG %]
organizationalUnitName = Organizational Unit Name (eg, section)
organizationalUnitName_default = ~TEXTLEVEL~
commonName = Common Name (eg, YOUR name)
commonName_max = 64
commonName_default = ~LEVEL~.[% DOMAIN %]
emailAddress = Email Address
emailAddress_max = 64
emailAddress_default = ~EMAIL~
 
[ req_attributes ]
challengePassword = A challenge password
challengePassword_min = 4
challengePassword_max = 20
 
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
nsCaRevocationUrl = [% CA_CRL %]
 
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
nsCaRevocationUrl = [% CA_CRL %]
 
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
nsCaRevocationUrl = [% CA_CRL %]
_END_TEMPLATE_

    return $the_template;
}
=head1 NAME

pkild::Model::Certificates - Catalyst File Model

=head1 SYNOPSIS

See L<pkild>

=head1 DESCRIPTION

L<Catalyst::Model::File> Model storing files under
L<>

=head1 AUTHOR

James White

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
