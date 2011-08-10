package pkild::Model::Certificates;

use strict;
use base 'Catalyst::Model::File';
use Path::Class 'file';
use Cwd;

__PACKAGE__->config( node_separator => '::');

sub cert_subject{
    my $self=shift;
    print STDERR "enter cert_subject\n" if $self->{'trace'};
    my $cert_file=shift;
    my $subject=undef;
    if(-f "$cert_file"){
        my $cacert_fh = FileHandle->new;
        if ($cacert_fh->open("< $cert_file")) {
            while(my $line=<$cacert_fh>){
                if($line=~m/\s*Subject:\s*(.*)/){
                   $subject=$1;
                }
            }
            $cacert_fh->close;
        }
    }else{
        print STDERR "Cannot open Certificate file: $cert_file\n";
        print STDERR "exit cert_subject undef\n" if $self->{'trace'};
        return undef;
    }
    print STDERR "exit cert_subject with subject\n" if $self->{'trace'};
    return $subject;
}

sub rootdir{
    my $self = shift;
    return join("/",@{ $self->{'root_dir'}->{'dirs'} });
}

sub csr_subject{
    my ($self, $csr) =@_;
    # write out the csr to a temp file and get the Subject: String
    my $tmpdir = tempdir( 'CLEANUP' => 1 );
    my ($fh, $filename) = tempfile( 'DIR' => $tmpdir );
    print $fh $csr;
    my $common_name;
    my $subject;
    open(GETCN, "/usr/bin/openssl req -in $filename -noout -text | ");
    while(my $line=<GETCN>){  
        if($line=~m/Subject:/){
            $subject=$line;
            $line=~s/.*[Cc][Nn]=//g;
            $line=~s/\/.*//g;
            $line=~s/\s+//g;
            $common_name=$line;
        }
    }
    chomp($subject);
    $subject=~s/\s+$//;
    $subject=~s/^\s+//;
    $subject=~s/^[Ss]ubject:\s*//;
    my @subject_parts=split(",",$subject);  
    my @dir_parts;
    for(my $idx=0; $idx<=$#subject_parts; $idx++){
        $subject_parts[$idx]=~s/^\s+//g;
        $subject_parts[$idx]=~s/\s+=/=/g;
        $subject_parts[$idx]=~s/=\s+/=/g;
        if($subject_parts[$idx]=~m/^[Cc][Nn].*\/.*/){
            my ($key,$value);
            my ($cn,$email)=split("\/",$subject_parts[$idx]);
            ($key,$value)=split("=",$cn);
            $key=~tr/A-Z/a-z/;
            $cn="$key=$value";
            $common_name=$value;
            push(@dir_parts,$cn);
            ($key,$value)=split("=",$email);
            $key=~tr/A-Z/a-z/;
            $email="$key=$value";
            $subject_parts[$idx]="$cn/$email";
        }else{
            my ($key,$value)=split("=",$subject_parts[$idx]);
            $key=~tr/A-Z/a-z/;
            $subject_parts[$idx]="$key=$value";
            push(@dir_parts,$subject_parts[$idx]);
        }
    }
    return join(', ',@subject_parts);
}

sub ca_basedn{
    my ($self,$ca_basedn) = @_;
    $self->{'ca_basedn'}=$ca_basedn if $ca_basedn;
    return $self->{'ca_basedn'} if $self->{'ca_basedn'};
    return undef;
}
################################################################################
# we'll expect to find the certificate tree defined in the ca-basedn TXT record
################################################################################
sub cert_dn_tree{
    my ($self,$dnsdomain,$orgunit) = @_;
    my $domain=$self->dnsdomainname();
    print STDERR "enter cert_dn_tree\n" if $self->{'trace'};
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my @components=split(",",$self->{'ca_basedn'});
    for(my $idx=0; $idx<=$#components; $idx++){
        my ($key,$val) = split(/=/,$components[$idx]);
        $key=~s/^\s//; $key=~s/\s$//;
        $val=~s/^\s//; $val=~s/\s$//;
        $key=~tr/A-Z/a-z/;
        $components[$idx]="$key=$val";
    }
    my $dir_path=join('/',@components,"ou=$domain");
    if(! -d "$rootdir/$dir_path/ou=$orgunit"){
        print STDERR "Not found: $rootdir/$dir_path/ou=$orgunit\n";
        return undef;
    }else{
        return $self;
    }
    print STDERR "exit cert_dn_tree undef\n" if $self->{'trace'};
    return undef;
}

sub user_cert_file{
    my ($self,$session) = @_;
    my $domain=$self->dnsdomainname();
    my $user_cert_dn=$self->user_cert_dn($session);
    print STDERR "user_cert_dn: $user_cert_dn\n";
    return undef unless ($user_cert_dn);
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });

    #print STDERR "rootdir: $rootdir\n";

    my @subject_parts=split(",",$user_cert_dn);  
    my @dir_parts; my $common_name;
    for(my $idx=0; $idx<=$#subject_parts; $idx++){
        $subject_parts[$idx]=~s/^\s+//g;
        $subject_parts[$idx]=~s/\s+=/=/g;
        $subject_parts[$idx]=~s/=\s+/=/g;
        if($subject_parts[$idx]=~m/^([Cc][Nn]|[Uu][Ii][Dd]).*\/.*/){
            my ($key,$value);
            my ($cn,$email)=split("\/",$subject_parts[$idx]);
            ($key,$value)=split("=",$cn);
            $key=~tr/A-Z/a-z/;
            $cn="$key=$value";
            $common_name=$value;
            push(@dir_parts,$cn);
            ($key,$value)=split("=",$email);
            $key=~tr/A-Z/a-z/;
            $email="$key=$value";
            $subject_parts[$idx]="$cn/$email";
        }else{
            my ($key,$value)=split("=",$subject_parts[$idx]);
            $key=~tr/A-Z/a-z/;
            $subject_parts[$idx]="$key=$value";
            push(@dir_parts,$subject_parts[$idx]);
        }

    }
    my $user_cert_file= $rootdir."/".join("/",@dir_parts)."/$common_name.crt";
    print STDERR "user_cert_file: $user_cert_file\n";
    return $user_cert_file;
}

sub user_cert_dir{
    my ($self,$session) = @_;
    my $user_cert_file=$self->user_cert_file($session);
    $user_cert_file=~s/\/[^\/]*$//;
    return $user_cert_file;
}

sub user_parent_cert_dir{
    my ($self,$session) = @_;
    my $user_parent_cert_dir=$self->user_cert_file($session);
    $user_parent_cert_dir=~s/\/ou=.*//;
    return $user_parent_cert_dir;
}

sub user_cert_exists{
    my ($self,$session) = @_;
    my $user_cert_file = $self->user_cert_file($session);
    print STDERR "user_cert_file: $user_cert_file\n";
    if( -f $user_cert_file){
        # we should probably validate the cert here
        return 1;
    }else{ 
        return undef;
    }
}

sub attr_for{
    my ($self,$session,$attr)=@_;
    my $user_cert_dn=$self->user_cert_dn($session);
    if($attr eq "domainName"){ return $self->object_domain( $self->objectname($session) ); }
    my @subject_parts=split(",",$user_cert_dn);
    my $common_name;
    for(my $idx=0; $idx<=$#subject_parts; $idx++){
        $subject_parts[$idx]=~s/^\s+//g;
        $subject_parts[$idx]=~s/\s+=/=/g;
        $subject_parts[$idx]=~s/=\s+/=/g;
        if($subject_parts[$idx]=~m/^[Cc][Nn].*\/.*/){
            my ($key,$value);
            my ($cn,$email)=split("\/",$subject_parts[$idx]);
            ($key,$value)=split("=",$cn);
            $key=~tr/A-Z/a-z/;
            $cn="$key=$value";
            $common_name=$value;
            if($attr eq "commonName"){ return $common_name; }
            ($key,$value)=split("=",$email);
            $key=~tr/A-Z/a-z/;
            if($attr eq "emailAddress"){ return $value; }
        }else{
            my ($key,$value)=split("=",$subject_parts[$idx]);
            $key=~tr/A-Z/a-z/;
            $subject_parts[$idx]="$key=$value";
            if(($key eq "c") && ($attr eq "countryName")){ return $value; }
            if(($key eq "st") && ($attr eq "stateOrProvinceName")){ return $value; }
            if(($key eq "l") && ($attr eq "localityName")){ return $value; }
            if(($key eq "o") && ($attr eq "organizationName")){ return $value; }
            if(($key eq "ou") && ($attr eq "organizationalUnitName")){ return $value; }
        }
    }
}

sub user_cert_dn{
use FileHandle;
    my ($self,$session) = @_;
    print STDERR "enter user_cert_dn\n" if $self->{'trace'};
    my $objectname = $self->objectname($session);
    #print STDERR "objectname: $objectname\n";
    my $cn=$objectname;
    my $domain=$self->dnsdomainname();
    my $type=undef;
    my $orgunit=undef;

    $cn=~s/,.*//g;
    $cn=~tr/A-Z/a-z/;
    my $subject;
    if($cn=~m/\s*uid=(.*)/){ 
        $type="user"; 
        $cn=~s/\s*uid=//;
        $subject = $self->ca_basedn().",ou=".$self->dnsdomainname().",ou=People,uid=$cn/emailaddress=$cn\@$domain";
    }
    if($cn=~m/\s*cn=(.*)/){ 
        $type="host";  
        $cn=~s/\s*cn=//;
        $subject = $self->ca_basedn().",ou=".$self->dnsdomainname().",ou=Hosts,cn=$cn.$domain/emailaddress=root\@$cn.$domain";
    }
    #print STDERR "exit user_cert_dn with [$subject]\n";
    return $subject;
}

sub objectname{
    my $self=shift;
    print STDERR "enter objectname\n" if $self->{'trace'};
    my $user_session=shift;
    print STDERR Data::Dumper->Dump([ $user_session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'} ]);
    if(defined($user_session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'})){
        print STDERR "exit objectname with objectname\n" if $self->{'trace'};
        return $user_session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'};
    }
    print STDERR "exit objectname undef\n" if $self->{'trace'};
    return undef;
}

sub object_domain{
    my $self=shift;
    print STDERR "enter object_domain\n" if $self->{'trace'};
    my $object=shift;
    my ($identity_type, $identity,$orgunit,$domain);
    if($object=~m/\s*(.*)\s*=\s*(.*)\s*,\s*[Oo][Uu]\s*=\s*([^,]+)\s*,\s*dc\s*=\s*(.*)\s*/){
        $identity_type=$1; $identity=$2; $orgunit=$3; $domain=$4; $domain=~s/,\s*dc=/./g;
        # I hate upper case.
        $identity_type=~tr/A-Z/a-z/;
        $identity=~tr/A-Z/a-z/;
        $orgunit=~tr/A-Z/a-z/;
        $domain=~tr/A-Z/a-z/;
    }
    foreach my $map (@{ $self->{'personal_cert_remap'} }){
        if($domain eq $map->{'auth_domain'}){
            $domain = $map->{'cert_domain'};
        }
    }
    if($domain){
        print STDERR "exit object domain with domain\n" if $self->{'trace'};
        return $domain;
    }
    print STDERR "exit object domain undef\n" if $self->{'trace'};
    return undef;
}

sub domain_trust_chain{
use File::Slurp;
    my $self = shift;
    print STDERR "enter domain_trust_chain\n" if $self->{'trace'};
    my $domain=shift;
    my $cert=undef;
    if ( -f $self->ca_for($domain)."/".$domain.".crt"){ 
        $cert = read_file( $self->ca_for($domain)."/".$domain.".crt", binmode => ':raw' ) ;        
    }elsif ( -f $self->ca_for($domain)."/".$domain.".pem"){ 
        $cert = read_file( $self->ca_for($domain)."/".$domain.".pem", binmode => ':raw' ) ;        
    }else{
        $cert = "File not found.";
    }
    print STDERR "exit domain_trust_chain with cert\n" if $self->{'trace'};
    return $cert;
}

################################################################################
# Return a list of hashes of lists of hashes that describe the directory tree
################################################################################
sub tree{
    my ($self, $c)=@_;
    print STDERR "enter tree\n" if $self->{'trace'};
    my $tree;
    my @file_names=$self->list(mode => 'both', recurse =>1);
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    $rootdir=~s/^\///;
    @file_names=sort(@file_names);
    my $previous_node='';
    my $type;
    for my $node (@file_names){
        next if $node eq '.';
        # skip directories containing key data and used for work.
        next if $node=~m/\/private$/;
        next if $node=~m/\/.rnd$/;
        #next if $node=~m/\/openssl.cnf$/;
        #next if $node=~m/\/csr$/;
        next if $node=~m/\/chain$/;
        next if $node=~m/\/index.txt$/;
        next if $node=~m/\/serial$/;
        next if $node=~m/\/crlnumber$/;
        next if $node=~m/\.old$/;
        next if $node=~m/\.attr$/;
        next if $node=~m/\/newcerts$/;
        #next if $node=~m/\/crl$/;
        #next if $node=~m/\.pem$/;
        next if $node=~m/\.csr$/;
        next if $node=~m/\.p12$/;
        # We need to know if this is a file, or a directory
        $type="unknown";
        if( -d $node){ $type="folder"; }
        if( -f $node){ $type="file"; }
        $node=~s/$rootdir//g;
        $node=~s/^\///g;
        if(! defined $tree->{$node}){  
            my @nodeparts=split("\/",$node);
            $node=~s/\//$self->{'node_separator'}/g;
            $tree->{$node} = { 
                               'attributes' => { 'id' => unpack("H*",$node), 'rel' => $type },
                               'data'       => $nodeparts[$#nodeparts],
                             };
            pop(@nodeparts);
            my $updir=join("$self->{'node_separator'}",@nodeparts);
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
    print STDERR "exit tree\n" if $self->{'trace'};
    return $tree->{''}->{'children'};
}

sub actual_node{
    my $self=shift;
    print STDERR "enter actual_node\n" if $self->{'trace'};
    my $unpacked_node=shift;
    print STDERR "exit actual_node\n" if $self->{'trace'};
    return pack("H*",$unpacked_node);
}

sub has_certificate{
    my ($self, $object)=@_;
    print STDERR "enter has_certificate\n" if $self->{'trace'};
    print STDERR "exit has_certificate\n" if $self->{'trace'};
    return undef;
}

sub ca_domain_from_file{
use FileHandle;
   my $self=shift;
   print STDERR "enter ca_domain_from_file\n" if $self->{'trace'};
   my $file=shift;
   my $fh = FileHandle->new;
   my $ca_domain;
   my $got_ca=0;
   if ($fh->open("< $file")) {
       while(my $line=<$fh>){
           chomp($line);
           if($line=~m/^\s*0.organizationalUnitName_default\s*=\s*(.*)/){
               $ca_domain=$1; 
               $ca_domain=~s/^\s*//g;
               $ca_domain=~s/\s*$//g;
           }
           if($line=~m/^\s*1.organizationalUnitName_default\s*=\s*(.*)/){
               if($1 =~m/^\s*Certificate Authority\s*$/){
                   $got_ca = 1;
               }
           }
       }
       $fh->close;
   }
   print STDERR "exit ca_domain_from_file\n" if $self->{'trace'};
   if($got_ca == 1){ return $ca_domain; }
   return '';
}

sub find_file{
    my ($self,$dir,$fileregex)=@_; 
    print STDERR "enter find_file\n" if $self->{'trace'};
    opendir(DIR,$dir);
    if ($dir !~ /\/$/) { $dir .= "/"; }
    my @dirlist=readdir(DIR);
    closedir(DIR);
    # why is this here? splice(@dirlist,0,2);
    foreach my $file (@dirlist){
        if($file ne "." && $file ne ".."){
            my $file = $dir.$file;
            if (-d $file){
                $self->find_file($file,$fileregex);
            }else{
                if($file=~m/$fileregex/){
                   push( @{$self->{'file_list'} },$file)
                }
            }
        }
    }
    print STDERR "exit find_file\n" if $self->{'trace'};
    return $self;
}

sub opensslcnf_for{
    use Template;
    my ($self,$session)=@_;
    my $tpl_data={};
    my $output='';
    my $tt=Template->new();
    my $user_cert_dir=$self->user_cert_dir($session);
    my $opensslcnf= "################################################################################
#                                                                              #
# Create your key with:                                                        #
# /usr/bin/openssl genrsa -out \$(hostname -f).key 2048                         #
#                                                                              #
# Create your Certificate Signing Request with:                                #
# /usr/bin/openssl req -new -sha1 -days 90 -key \$(hostname -f) \\               #
#                      -out \$(hostname -f).csr -config openssl.cnf -batch      #
# (using this openssl.cnf)                                                     #
#                                                                              #
# Then paste the contents of the resulting *.csr into the textarea             # 
# The \"Download your Certificate\" link to retrieve and install your Cert       # 
################################################################################

[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
[\% req_distinguished_name \%]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
# Additional things you might add to v3_req:
# subjectAltName=DNS:www.websages.com,DNS:www.wcyd.org,DNS:on.yermom.now
";
    my $cnf_attrs = [ 
                      'domainName',
                      'organizationName',
                      'organizationalUnitName',
                      'commonName',
                      'emailAddress',
                      'nsCaRevocationUrl'
                    ];
    foreach my $cnf_attr (@{ $cnf_attrs }){
        $tpl_data->{$cnf_attr} = $self->attr_for($session,$cnf_attr);
    }
    $tpl_data->{'req_distinguished_name'} = $self->reqdn_block($user_cert_dir);
    $tt->process(\$opensslcnf,$tpl_data,\$output);
    return $output;
}

sub create_certificate{
use File::Slurp;
    my ($self, $param, $session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my $objectname = $self->objectname($session);
    my $cn = $objectname;
    my $domain=$self->dnsdomainname();
    my $user_cert_dir=$self->user_cert_dir($session);
    my $user_cert_file=$self->user_cert_file($session);
    my $user_parent_cert_dir=$self->parent_ca($user_cert_dir);
    my ($subject,$type);
    $cn=~s/,.*//g;
    $cn=~tr/A-Z/a-z/;
    if($cn=~m/\s*uid=(.*)/){
        $type="user";
        $cn=~s/\s*uid=//;
        $subject = $self->ca_basedn().", ou=People, cn=$cn/emailaddress=$cn\@$domain";
    }
    if($cn=~m/\s*cn=(.*)/){
        $type="host";
        $cn=~s/\s*cn=//;
        $subject = $self->ca_basedn().", ou=Hosts, cn=$cn.$domain/emailaddress=root\@$cn.$domain";
    }
    print STDERR "\nuser_cert_dir: $user_cert_dir\n\n";
    if(! -d "$user_cert_dir"){
        mkdir("$user_cert_dir",0700);
    }
    ############################################################################    
    # Create an openssl.cnf in the $user_cert_dir 
    ############################################################################    
    open(SSLCNF,">$user_cert_dir/openssl.cnf");
    print SSLCNF $self->opensslcnf_for($session);
    close(SSLCNF);

    ############################################################################    
    # create the private key
    ############################################################################    
    if(! -d "$user_cert_dir/private"){
        mkdir("$user_cert_dir/private",0700);
    }
    system("/usr/bin/openssl genrsa -out \"$user_cert_dir/private/key\" 2048");

    ############################################################################    
    # create the CSR
    ############################################################################    
    system("/usr/bin/openssl req -new -sha1 -days 90 -key \"$user_cert_dir/private/key\"  -out \"$user_cert_dir/csr\" -config \"$user_cert_dir/openssl.cnf\" -batch");

    ############################################################################    
    # Ensure the DN is correct
    ############################################################################    
    open(VERIFY,"openssl req -text -noout -in \"$user_cert_dir/csr\"|");
    while(my $line=<VERIFY>){
        # do something else here, yo
        print STDERRR $line;
    }
    close(VERIFY);
 
    ############################################################################    
    # if it's valid, Sign it with the parent
    ############################################################################    
    system("/usr/bin/openssl ca -config \"$user_parent_cert_dir/openssl.cnf\" -days 90 -policy policy_anything -out \"$user_cert_file\" -batch -infiles \"$user_cert_dir/csr\"");

    ############################################################################    
    # convert to a pkcs12 container with the passphrase
    ############################################################################    
    my $passphrase=$param->{'password'};
    system("/bin/echo \'$param->{'password'}\' | /usr/bin/openssl pkcs12 -export -clcerts -passout fd:0 -in \"$user_cert_file\" -inkey \"$user_cert_dir/private/key\" -out \"$user_cert_dir/p12\"");

    ############################################################################    
    # read in the content fo the pkcs12 cert to memory
    ############################################################################    
    my $pkcs12data = read_file( '$user_cert_dir/p12', binmode => ':raw' ) ;        

    ############################################################################    
    # remove the pkcs12 cert from disk
    ############################################################################    
    unlink("$user_cert_dir/p12");

    ############################################################################    
    # remove the key from disk
    ############################################################################    
    unlink("$user_cert_dir/private/key");
    if(-d "$user_cert_dir/private"){
        rmdir("$user_cert_dir/private");
    }

    ############################################################################    
    # return the content of the pkcs12 cert as a blob for file transfer to the client
    ############################################################################    
    return $pkcs12data;
}

sub remove_certificate{
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir = $self->actual_node($param->{'node_name'});
    my @nodepart=split(/$self->{'node_separator'}/, $node_dir);
    my $node_name=pop(@nodepart); pop(@nodepart);
    my $parent_name=$nodepart[$#nodepart];
    my $parent_dir="$rootdir/".join("/",@nodepart);
    $node_dir=~s/$self->{'node_separator'}/\//g;
    $node_dir="$rootdir/$node_dir";
    if( -d "$node_dir/private"){
        opendir(my $pdh, "$node_dir/private");
        my @pfiles = readdir($pdh);
        foreach my $pfile (@pfiles){
            unlink("$node_dir/private/$pfile");
        }
        closedir $pdh;
        rmdir "$node_dir/private";
    }
    opendir(my $dh, "$node_dir");
    my @files = readdir($dh);
    foreach my $file (@files){
        unlink("$node_dir/$file");
    }
    closedir $dh;
    rmdir "$node_dir";
}

sub trustchain_for{
    my ($self, $session)=@_;
    my $pdir = $self->user_parent_cert_dir($session);
    if(-f "$pdir/chain"){
        my $trustchain='';
        open(TRUSTCHAIN,"$pdir/chain");
        while(my $line=<TRUSTCHAIN>){
            $trustchain.=$line;
        }
        close(TRUSTCHAIN);
        return $trustchain;
    }else{
        return "File not found.\n";
    }
}

sub certificate_for{
    my ($self, $session)=@_;
    my $user_cert_file=$self->user_cert_file($session);
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    if(-f "$user_cert_file"){
        my $user_cert='';
        open(USERCERT,"$user_cert_file");
        while(my $line=<USERCERT>){
            $user_cert.=$line;
        }
        close(USERCERT);
        return $user_cert;
    }else{
        return "File not found.\n";
    }
}

sub certificate_sign{
    my ($self, $session, $csr)=@_;
    my $csr_subject=$self->csr_subject($csr);
    my $user_cert_dn=$self->user_cert_dn($session);
    my $ca_cert_dn=$self->user_cert_dn($session);
    if( $csr_subject eq $user_cert_dn ){
        my $user_cert_dir=$self->user_cert_dir($session);
        if(! -d "$user_cert_dir"){ mkdir($user_cert_dir,0750); };
        # write out the CSR
        if( ! -f "$user_cert_dir/csr"){ 
            open(CSR, ">$user_cert_dir/csr");
            print CSR "$csr";
            close(CSR);
        }
        my $user_cert_file=$self->user_cert_file($session);
        # get the parent dir
        my $pdir = $self->user_parent_cert_dir($session);
        # sign the csr with the parent cert
        system("/usr/bin/openssl ca -config \"$pdir/openssl.cnf\" -policy policy_anything -out \"$user_cert_file\" -batch -infiles \"$user_cert_dir/csr\"");
    }else{
        return undef;
    }
}

sub revoke_user_certificate{
    my ($self, $params, $session)=@_;

    my $user_cert_file=$self->user_cert_file($session);
    my $user_cert_dir=$self->user_cert_dir($session);
    my $parent_ca = $self->parent_ca($user_cert_dir);

print STDERR "user_cert_file: $user_cert_file\n";
print STDERR "user_cert_dir: $user_cert_dir\n";
print STDERR "parent_ca: $parent_ca\n";
    system("/usr/bin/openssl ca -revoke \'$user_cert_file\' -keyfile \'$parent_ca/private/key\' -cert \'$parent_ca/pem\' -config \'$parent_ca/openssl.cnf\'");
    if($? == 0){
        # update the Certificate Revocation list
        system("/usr/bin/openssl ca -gencrl -keyfile \'$parent_ca/private/key\' -cert \'$parent_ca/pem\' -config \'$parent_ca/openssl.cnf\' -out \'$parent_ca/crl\'");
        if($? == 0){
            opendir(my $dh, "$user_cert_dir");
            my @files = readdir($dh);
            foreach my $file (@files){
                unlink("$user_cert_dir/$file");
            }
            closedir $dh;
            if( -d "$user_cert_dir"){ rmdir "$user_cert_dir"; };
            if( -d "$user_cert_dir"){ print STDERR "Unable to remove $user_cert_dir\n" };
        }else{
            print STDERR "Unable to update the Certificate Revokation list\n";
        }
    }else{
        print STDERR "Unable to revoke certificate.\n";
    }
    return $self;
}

# depricated
sub revoke_certificate{
    my ($self, $param, $session)=@_;
    print STDERR "enter revoke_certificate\n" if $self->{'trace'};
    my $rootdir = $self->rootdir;

    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir = $self->actual_node($param->{'node_name'});
    my @nodepart=split(/$self->{'node_separator'}/, $node_dir);
    my $node_name=pop(@nodepart); pop(@nodepart);
    my $parent_name=$nodepart[$#nodepart];
    my $parent_dir="$rootdir/".join("/",@nodepart);
    $node_dir=~s/$self->{'node_separator'}/\//g;
    $node_dir="$rootdir/$node_dir";

return $self;
#    chdir ($parent_dir);
#    if( ! -f "$parent_dir/crlnumber"){
#        open(CRLINDEX,">$parent_dir/crlnumber");
#        print CRLINDEX "01\n";
#        close(CRLINDEX);
#    }
#    # Revoke the Certificate (updates the Index)
#    system("/usr/bin/openssl ca -revoke $node_dir/$node_name.crt -keyfile $parent_dir/private/$parent_name.key -cert $parent_dir/$parent_name.pem -config $parent_dir/openssl.cnf");
#
#    # update the Certificate Revocation list
#    system("/usr/bin/openssl ca -gencrl -keyfile $parent_dir/private/$parent_name.key -cert $parent_dir/$parent_name.pem -config $parent_dir/openssl.cnf -out $parent_dir/$parent_name.crl");
#
#    # Rename the cert to indicate it has been revoked
#    rename("$node_dir/$node_name.crt","$node_dir/$node_name.revoked");
#    print STDERR "exit revoke_certificate\n" if $self->{'trace'};
    return $self;  
}

sub sign_certificate{
    use FileHandle;
    use File::Temp qw/ tempfile tempdir /;
    my ($self, $param,$session,$admin)=@_;
    print STDERR "enter sign_certificate\n" if $self->{'trace'};
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    
    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir;
    if(! defined($param->{'node_name'} )){
        $node_dir = $self->actual_node(
                                       $self->actual_node_from_objectname(
                                                                          $self->objectname($session->{'user'})
                                                                         )
                                      );
        # Strip off the last node as it's the user/host
        $node_dir=~s/::[^:]+$//;
    }else{
        $node_dir = $self->actual_node($param->{'node_name'});
    }
    $node_dir=~s/$self->{'node_separator'}/\//g;
    $node_dir=~s/certs$//g;
    $node_dir="$rootdir/$node_dir";

    # write out the csr to a temp file and get the Subject: String
    my $tmpdir = tempdir( 'CLEANUP' => 1 );
    my ($fh, $filename) = tempfile( 'DIR' => $tmpdir );
    print $fh $param->{'csr_input'};
    my $common_name;
    my $subject;
    open(GETCN, "/usr/bin/openssl req -in $filename -noout -text | ");
    while(my $line=<GETCN>){
        if($line=~m/Subject:/){
            $subject=$line;
            $line=~s/.*CN=//g;
            $line=~s/\/.*//g;
            $line=~s/\s+//g;
            $common_name=$line;
        }
    }
    chomp($subject);
    $subject=~s/\s+$//;
    $subject=~s/^\s+//;
    $subject=~s/^[Ss]ubject:\s*//;
    ############################################################################
    # Do not let a non-administrator sign a cert that isn't his/it's
    ############################################################################
    if(($admin == 0) && ($subject ne $self->user_cert_dn($session->{'user'})) ){
        print STDERR  "WARNING: ".$self->objectname($session->{'user'})." attempted to sign [$subject]\n";
        return undef;
    }
    # create the $root/$param->{'node_name'};/$cn  directory
    if(! -d "$node_dir/certs/$common_name"){
        mkdir("$node_dir/certs/$common_name",0700);
    }
    my $csrfh = FileHandle->new("> $node_dir/certs/$common_name/$common_name.csr");
    # write out the csr to ${cn}.csr in the node directory
    if (defined $csrfh) {
        print $csrfh $param->{'csr_input'};
        $csrfh->close;
    }
    # sign the csr and write it out as a ${cn}.crt int the node directory
    system("/usr/bin/openssl ca -config $node_dir/openssl.cnf -policy policy_anything -out $node_dir/certs/$common_name/$common_name.crt -batch -infiles $node_dir/certs/$common_name/$common_name.csr");
    print STDERR "enter sign_certificate\n" if $self->{'trace'};
    return "SUCCESS";
}

sub tree_init{
    my ($self,$path)=@_;
    my @ca_tree = split(/,/,$path);
    my $root_dir=$self->rootdir;
    my $ca_dir=$root_dir;
    my $domain=$self->dnsdomainname();

    # wtf am i doing here?
    for(my $idx=0; $idx<=$#ca_tree;$idx++){           
        $ca_tree[$idx]=~s/^\s+//;
        $ca_tree[$idx]=~s/\s+$//;
        $ca_tree[$idx]=~s/[\/\\\.]//;
        my ($key,$value)=split(/=/,$ca_tree[$idx]);
        $key=~tr/A-Z/a-z/;
        $ca_tree[$idx]="$key=$value";       
        $ca_dir.="/$ca_tree[$idx]";
        if(! -d "$ca_dir"){ 
            mkdir($ca_dir,0750); 
        }
    }

    # Create the root certificate authority for all organizations

    if(! -d "$root_dir/ou=Certificate Authority/cn=Intermediate"){ 
        $self->ca_initialize("$root_dir/ou=Certificate Authority/cn=Intermediate");
    }

    if(! -d "$ca_dir/ou=Certificate Authority/cn=Intermediate"){ 
        $self->ca_initialize("$ca_dir/ou=Certificate Authority/cn=Intermediate");
    }

    if(! -d "$ca_dir/ou=$domain/ou=Certificate Authority/cn=Intermediate"){ 
        $self->ca_initialize("$ca_dir/ou=$domain/ou=Certificate Authority/cn=Intermediate");
    }

    # now create some placeholders for our certs:
    if(! -d "$ca_dir/ou=$domain/ou=People"){ $self->mkdir("$ca_dir/ou=$domain/ou=People",0750); }
    if(! -d "$ca_dir/ou=$domain/ou=Hosts"){ $self->mkdir("$ca_dir/ou=$domain/ou=Hosts",0750); }

    return $self;
}

sub dnsdomainname{
    my ($self,$domain)=@_;
    $self->{'domain'}=$domain if $domain;
    return $self->{'domain'};
}

sub crl_base{
    my ($self,$crl_base)=@_;
    $self->{'crl_base'}=$crl_base if $crl_base;
    return $self->{'crl_base'};
}

sub parent_ca{
    my ($self, $dir) = @_;
    my @path=split('/', $dir); 
    my $l_s_dir=pop(@path);
    if($l_s_dir eq "cn=Root"){                   # a root ca is it's own parent
        return $dir;
    }elsif($l_s_dir eq 'cn=Intermediate'){       # an ICA can have several parents depending on what exists

        if(join('/',@path) eq $self->rootdir."/ou=Certificate Authority"){ # If it's the top-level ICA, then it's root is samelevel
            return join('/',@path)."/cn=Root";
        }
        if(-d join('/',@path).'/cn=Root'){
            return join('/',@path)."/cn=Root";
        }else{                                   # otherwise we look to the parent's parent's Intermediate CA
            my $parent_dn=pop(@path);
            my $grandparent_dn=pop(@path);
            return join('/',@path)."/ou=Certificate Authority/cn=Intermediate";
        }
    }else{                                       # any other cn we look to the parent's Intermediate CA
        my $parent_dn=pop(@path);
        return join('/',@path)."/ou=Certificate Authority/cn=Intermediate";
    }
    return undef;
}

sub mkdir{
    my ($self,$path,$mode)=@_;
    my @path = split(/\//,$path);
    my $newdir = shift(@path);
    while(my $dir = shift(@path)){
        $newdir.="/$dir";
        if(! -d $newdir){
            mkdir($newdir,$mode);
        }
    }
}

sub level_of{
    my ($self, $dir) = @_;
    my $rootdir = $self->rootdir;
    $dir=~s/^$rootdir\///;
    # print STDERR "Level of: $dir\n";
    my @path=split('/',$dir);
    my $basename = pop(@path);
    my $level = $#path;
    if($basename eq "cn=Root"){ return $level; }
    if($basename eq "cn=Intermediate"){ return $level + 1; }
    my $parentname = pop(@path);
    if($basename eq "ou=Hosts"){ return $level + 2; }
    if($basename eq "ou=People"){ return $level + 3; }
    return 8; 
}

sub reqdn_block{ # Create the req_distinguished_name block of our openssl.crt
    my ($self,$dir) = @_;
    my $rootdir = $self->rootdir;
    $dir=~s/^$rootdir\///;
    my @path=split('/',$dir);
    my @rdnlines;
    my ($o, $ou, $cn) = (0, 0, 0);
    while (my $d = shift(@path)){
        if($d=~m/^o=(.*)/){
            push(@rdnlines,"$o.organizationName = Organization Name (eg, company)");
            push(@rdnlines,"$o.organizationName_default = $1");
            $o++;
        }elsif($d=~m/^ou=(.*)/){
            push(@rdnlines,"$ou.organizationalUnitName = Organizational Unit Name (eg, section)");
            push(@rdnlines,"$ou.organizationalUnitName_default = $1");
            $ou++;
        }elsif($d=~m/^cn=(.*)/){
            push(@rdnlines,"$cn.commonName = Organizational Unit Name (eg, section)");
            push(@rdnlines,"$cn.commonName_max = 64");
            push(@rdnlines,"$cn.commonName_default = $1");
            $cn++;
        }elsif($d=~m/^uid=(.*)/){
            push(@rdnlines,"userId = User ID (eg, account)");
            push(@rdnlines,"userId_max = 20");
            push(@rdnlines,"userId_default = $1");
            push(@rdnlines,"emailAddress = Email Address"); 
            push(@rdnlines,"emailAddress_max = 64");
            push(@rdnlines,"emailAddress_default = $1@".$self->dnsdomainname());
        }
    }
    # not sure how to determine the domain
    #push(@rdnlines,"$cn.emailAddress = Email Address"); 
    #push(@rdnlines,"$cn.emailAddress_max = 64");
    #push(@rdnlines,"$cn.emailAddress_default = certificates@");
    return(join("\n",@rdnlines));
}

# Create a certificate authority in the provided directory, sign with the $parent (dir) if provided, else self-sign
sub ca_initialize{
    my ($self, $dir)=@_;

    $self->mkdir($dir,0755); 
    if(! -d $dir){ return $self; } # failure to create causes an infinite loop on cn=Root dirs

    my $domain = $self->{'domain'};
    my $crl_path = $self->{'crl_base'};
    my $level=0;

    my $parent_ca = $self->parent_ca($dir);
    #if($dir eq $parent_ca){ return $self; } # infinite loop detection
    if(! -d "$parent_ca"){
        $self->ca_initialize($parent_ca);
    }
    my $level = $self->level_of($dir);
    #print STDERR "level: $level\n";


    if(! -d "$dir/certs"){ mkdir("$dir/private",0750); }
    if(! -d "$dir/newcerts"){ mkdir("$dir/newcerts",0750); }
    if(! -d "$dir/private"){ mkdir("$dir/private",0750); }
    if(! -f "$dir/serial"){
        my $fh = FileHandle->new("> $dir/serial");
        if (defined $fh) { print $fh "01\n"; $fh->close; }
    }
    if(! -f "$dir/crlnumber"){
        my $fh = FileHandle->new("> $dir/crlnumber");
        if (defined $fh) { print $fh "01\n"; $fh->close; }
    }
    if(! -f "$dir/index.txt"){
        my $fh = FileHandle->new("> $dir/index.txt");
        if (defined $fh) { print $fh ''; $fh->close; }
    }
    if(! -f "$dir/crl"){
        my $fh = FileHandle->new("> $dir/crl");
        if (defined $fh) { print $fh ''; $fh->close; }
    }
    
    # 
    # openssl.cnf # we assume a very particular directory structure here.
    #
    my $template=Template->new();
    my $tpldata;
    $tpldata->{'req_distinguished_name'} = $self->reqdn_block($dir);
    $tpldata->{'ca_domain'}=$domain;
    $tpldata->{'cert_home_dir'}="\"$dir\"";
    $tpldata->{'ca_orgunit'}="$dir";
    $tpldata->{'ca_orgunit'}=~s/.*\///;
    $tpldata->{'ca_cn'} = $tpldata->{'ca_orgunit'};
    $tpldata->{'ca_email'}="certmaster\@$domain";
    $tpldata->{'crl_days'}="30";
    my $key_size=2048;
    ############################################################################
    # The level of the cert defines how long it is good for and how large the 
    #   key is, (larger keys used less often can live longer)
    # Level_0: The Pkild Root CA is good for 8 years, 
    #          (<strike>8192 bits</strike> 4096 bits) effin' apple can't do 8192
    # level_1: The Pkild ICA (and Optional Org Root CAs) 5 / 4096 bit
    # level_2: Organizational ICAs (and Optional Domain Root CAs) 3 years (4096 bits)
    # level_3: Domain ICAs are good for 2 years   (4096 bits)
    # level_4: Host certs are good for 1 year     (2048 bits)
    # level_5: People certs are good for 90 days  (2048 bits)
    # level_6: Testing certs are good for 30 days (1024 bits)
    # level_7+: Junk certs are good for 1 day      (512 bits)
    ############################################################################
    if($level == 0){
        $tpldata->{'ca_default_days'}="2920";
        $key_size=4096; # effin apple
    }elsif($level == 1){
        $tpldata->{'ca_default_days'}="1825";
        $key_size=4096;
    }elsif($level == 2){
        $tpldata->{'ca_default_days'}="1095";
        $key_size=4096;
    }elsif($level == 3){
        $tpldata->{'ca_default_days'}="730";
        $key_size=4096;
    }elsif($level == 4){
        $tpldata->{'ca_default_days'}="365";
        $key_size=2048;
    }elsif($level == 5){
        $tpldata->{'ca_default_days'}="90";
        $key_size=2048;
    }elsif($level == 6){
        $tpldata->{'ca_default_days'}="30";
        $key_size=1024;
    }else{
        $tpldata->{'ca_default_days'}="1";
        $key_size=512;
    }
    my $text = $self->openssl_cnf_template(); 

    my $map = { 'o'  => 'ca_org', };
    my $org;
    my @tree=split(/\//,$dir);
    foreach my $branch (@tree){
        my ($k,$v)=split(/=/,$branch);
        if(defined($map->{$k})){ 
            $tpldata->{ $map->{$k} }=$v; 
            $org=$v if($k eq 'ou');
        }
    }
    $tpldata->{'crl_path'}="$crl_path/$tpldata->{'ca_orgunit'}.crl";
    # let's not use spaces and capital letters in our uris...
    $tpldata->{'crl_path'}=~s/ /_/g;
    $tpldata->{'crl_path'}=~tr/A-Z/a-z/;
    $template->process(\$text,$tpldata,"$dir/openssl.cnf");
    # private.key
    system("/usr/bin/openssl genrsa -out \"$dir/private/key\" $key_size");
    # csr
    system("/usr/bin/openssl req -new -sha1 -days $tpldata->{'ca_default_days'} -key \"$dir/private/key\"  -out \"$dir/csr\" -config \"$dir/openssl.cnf\" -batch");
    # pem
    my $parent = $parent_ca;
    if($parent eq $dir){
        # self sign if we're our own parent
        system("openssl req -new -x509 -nodes -sha1 -days $tpldata->{'ca_default_days'} -key \"$dir/private/key\" -out \"$dir/pem\" -config \"$dir/openssl.cnf\" -batch");
    }else{
        # sign us with our parent
        system("/usr/bin/openssl ca -extensions v3_ca -days $tpldata->{'ca_default_days'} -out \"$dir/pem\" -in \"$dir/csr\" -config \"$parent/openssl.cnf\" -batch");
    }
#    # trustchain.pem
#    if(defined($parent)){
#        # OS X likes it this way, linux doesn't seem to care.
#        system("/bin/cat \"$parent/chain\" \"$dir/pem\" > \"$dir/chain\"");
#        # system("/bin/cat \"$dir/pem\" \"$parent/chain\" > \"$dir/chain\"");
#    }else{
#        system("/bin/cp \"$dir/pem\" \"$dir/chain\"");
#    }
    return $self;
}

sub ca_create{
    use FileHandle;
    use Template;
    my ($self, $param,$session)=@_;
    print STDERR "enter ca_create\n" if $self->{'trace'};
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });

    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir = $self->actual_node($param->{'node_name'});
    $node_dir=~s/new_root_ca/\//g; # get rid of the top node and make our root node_dir ""
    $node_dir=~s/$self->{'node_separator'}/\//g;
    $node_dir="$rootdir/$node_dir";
    my $template=Template->new();
    my $tpldata;
    if($param->{'ca_domain'}){
        if( ! -d "$node_dir/$param->{'ca_domain'}" ){
        
            # Create our working environment
            umask(0077);
            mkdir("$node_dir/$param->{'ca_domain'}",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/private",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/certs",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/newcerts",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/crl",0700); 
            # echo "01" > ${ROOT_CA}/serial
            if(! -f "$node_dir/$param->{'ca_domain'}/serial"){
                my $fh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/serial");
                if (defined $fh) {
                    print $fh "01\n";
                    $fh->close;
                }
            }
            # echo "01" > ${ROOT_CA}/crlnumber
            if(! -f "$node_dir/$param->{'ca_domain'}/crlnumber"){
                my $fh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/crlnumber");
                if (defined $fh) {
                    print $fh "01\n";
                    $fh->close;
                }
            }
            # cp /dev/null ${ROOT_CA}/index.txt
            if(! -f "$node_dir/$param->{'ca_domain'}/index.txt"){
                my $fh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/index.txt");
                if (defined $fh) {
                    print $fh '';
                    $fh->close;
                }
            }
            foreach my $key (keys(%{ $param } )){
                $tpldata->{$key} = $param->{$key};
            }
            foreach my $prefs (@{ $session->{'menudata'}->{'openssl_cnf_prefs'}->{'fields'} }){
                $tpldata->{$prefs->{'name'}} = $prefs->{'value'};
            }
          
            # Create a new openssl.cnf for this CA
            my $text=$self->openssl_cnf_template(); 
            $tpldata->{'cert_home_dir'}="$node_dir/$param->{'ca_domain'}";
            $template->process(\$text,$tpldata,"$node_dir/$param->{'ca_domain'}/openssl.cnf");

            # Create the private key
            system("/usr/bin/openssl genrsa -out $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key 4096");

            if( -d "$node_dir/certs"){
                # only the top-level dir will not have a certs dir , so this is a mid_ca (of some arbitrary level)
                
                # Create a CSR to be signed by our parent
                system("/usr/bin/openssl req -new -sha1 -days $tpldata->{'ca_default_days'} -key $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key  -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr -config $node_dir/$param->{'ca_domain'}/openssl.cnf -batch");

                # Have the parent sign the CSR
                system("/usr/bin/openssl ca -extensions v3_ca -days $tpldata->{'ca_default_days'} -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt -in $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr -config $node_dir/openssl.cnf -batch");
                # Clean up the CSR
#                if(-f "$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt"){
#                    unlink("$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr");
#                }

                # Write out the PEM part to the .pem file
                my $write=0;
                my $rfh = FileHandle->new;
                if ($rfh->open("< $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt")) {
                    my $wfh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem");
                    if (defined $wfh) {
                        while(my $line=<$rfh>){
                            if($line=~m/-----BEGIN CERTIFICATE-----/){ $write=1; }
                            if($write == 1){ print $wfh $line;}
                            if($line=~m/-----END CERTIFICATE-----/){ $write=0; }
                        }
                         $wfh->close;
                      
                    }
                    $rfh->close;
                }

                # Determine the name of our parent CA
                my $parent_name=$node_dir;
                $parent_name=~s/.*\///;

                # Write out the trust_chain
                # cat mid-ca.${DOMAIN}.crt root-ca.${DOMAIN}.pem > ca_trust_chain.crt
 
            }else{
                # only the top-level node_type is directory, so this is a root ca

                # Create a self-signed cert in .pem format
                system("/usr/bin/openssl req -new -x509 -nodes -sha1 -days $tpldata->{'ca_default_days'} -key $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key  -out /$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -config /$node_dir/$param->{'ca_domain'}/openssl.cnf -batch");

                # Write out the cert in x509 
                system("/usr/bin/openssl x509 -in $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -text -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt");
            }
            
            # In any event, create the empty certificate revocation list
            system("/usr/bin/openssl ca -gencrl -keyfile $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key -cert $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -config $node_dir/$param->{'ca_domain'}/openssl.cnf -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crl");
            # To Revoke: (run this and then regenerate the CRL with the command above, copy it to it's URI)
            #system("/usr/bin/openssl ca -revoke <PATH/TO/BAD_CERT> -keyfile $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key -cert $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -config $node_dir/$param->{'ca_domain'}/openssl.cnf");
            print STDERR "exit ca_create SUCCESS\n" if $self->{'trace'};
            return "SUCCESS";
        }
    }
    print STDERR "exit ca_create ERROR\n" if $self->{'trace'};
    return "ERROR";
}
################################################################################
# Given the domain name, we traverse the tree to find the top-level openssl.cnf
# that belongs to the domain, if there are more than one, we use the first
# If there are none, we look for root-ca.<domain>, and create a <domain> under
# it. If there is no root-ca.<domain>, we look for any root-ca, (the first if
# more than one) and create the <domain> under it. we then return the path
# to <domain> so we can do sub-ca (cert) operations under it.
################################################################################
sub ca_for{
    my ($self,$ca_domain)=@_;
    print STDERR "enter ca_for\n" if $self->{'trace'};
    my $rootdir = $self->rootdir;

    ############################################################################
    # find all the openssl.cnfs with ca_domain=$ca_domain
    $self->{'file_list'}=[];
    my @domain_cnfs;
    my @least_depth_domain_cnfs;
    $self->find_file($rootdir,"openssl.cnf");
    foreach my $cnf_file (@{ $self->{'file_list'} }){
       my $cnf_domain = '';
       my $cnf_domain = $self->ca_domain_from_file($cnf_file);
       if($cnf_domain eq $ca_domain){
           push(@domain_cnfs,$cnf_file);
       }
    }
    my $physical_path;
    my $leastdepth=0;
    if($#domain_cnfs >= 0){
       foreach my $domain_dir (@domain_cnfs){
           my $depth=split("/",$domain_dir);
           if(($leastdepth == 0)||($depth < $leastdepth)){
               $leastdepth=$depth;
           } 
       }
       # now that we know the minimum depth, find all that have it.
       foreach my $domain_dir (@domain_cnfs){
           my $depth=split("/",$domain_dir);
           if($leastdepth == $depth){
               push(@least_depth_domain_cnfs,$domain_dir);
           }
       }
       # now we sort them
       my @ordered_least_depth_domain_cnfs = sort(@least_depth_domain_cnfs);
       $physical_path = $least_depth_domain_cnfs[0];
       $physical_path =~s/\/openssl.cnf.*$//;
       print STDERR "exit ca_for\n" if $self->{'trace'};
       return $physical_path;
    }
    # if we can't find any, we return undef 
    print STDERR "exit ca_for undef\n" if $self->{'trace'};
    return undef;
}

sub actual_node_from_objectname{
    my $self=shift;
    print STDERR "enter actucal_node_from_objectname\n" if $self->{'trace'};
    my $objectname=shift;
    my $rootdir = $self->rootdir;
    my ($identity_type, $identity,$orgunit,$domain);
    if($objectname=~m/\s*([^,]*)\s*,\s*[Oo][Uu]\s*=\s*([^,]+)\s*,\s*dc\s*=\s*(.*)\s*/){
        $identity=$1; $orgunit=$2; $domain=$3; $domain=~s/,\s*dc=/./g;

        # I hate upper case.
        $identity_type=~tr/A-Z/a-z/;
        $identity=~tr/A-Z/a-z/;
        $orgunit=~tr/A-Z/a-z/;
        $domain=~tr/A-Z/a-z/;
    }
    my $search = "ou=$domain/ou=$orgunit/$identity";
    $self->find_file($rootdir,"openssl.cnf");
    my $cert_dir = undef;
    foreach my $cnf_file (@{ $self->{'file_list'} }){
        if($cnf_file=~m/$search\/openssl.cnf$/i){
            $cert_dir = "$cnf_file\n";
            $cert_dir =~ s/\/openssl.cnf$//;
            $cert_dir =~ s/^$rootdir\///;
            $cert_dir =~ s/\//::/g;
        }
    }
    return unpack("H*",$cert_dir);
}

# by convention, all CAs have a subdir named "certs" and others don't
sub node_type{
    my ($self, $unpacked_node)=@_;
    print STDERR "enter node_type\n" if $self->{'trace'};
    my $node = pack("H*",$unpacked_node);
    chomp($node);
    my @nodepart=split(/$self->{'node_separator'}/, $node);
    $node =~s/$self->{'node_separator'}/\//g;
    my $rootdir=$self->rootdir();
    if($node eq "new_root_ca"){ return "new_root_ca"; }
    if($node eq "certificate_authority"){ return "certificate_authority"; }
    if($node eq "new_cert"){ return "new_cert"; }
    if($node eq "logout"){ return "logout"; }
    if(-f "$rootdir/$node"){ return "file"; }
    ############################################################################     
    # These are conventions for type detection
    ############################################################################     
    # print STDERR "[ $rootdir ] [ $node ] [ $nodepart[$#nodepart] ]\n";
    if(-d "$rootdir/$node"){ 
        if($nodepart[$#nodepart] eq "cn=Root"){ return "ca";}
        if($nodepart[$#nodepart] eq "cn=Intermediate"){ return "ca";}
        if( ($nodepart[$#nodepart] =~ m/^cn=/) || ($nodepart[$#nodepart] =~ m/^uid=/)){ 
            if(-f "$rootdir/$node/$nodepart[$#nodepart].revoked"){
                print STDERR "exit node_type revoked_certificate\n" if $self->{'trace'};
                return "revoked_certificate" ;
            }
            print STDERR "exit node_type certificate\n" if $self->{'trace'};
            return "certificate" 
        }
        print STDERR "exit node_type directory\n" if $self->{'trace'};
        return "directory"; 
    }
    print STDERR "exit node_type undef\n" if $self->{'trace'};
    return undef;
}

sub contents{
    use FileHandle;
    my ($self, $unpacked_node)=@_;
    print STDERR "enter contents\n" if $self->{'trace'};
    my $node = pack("H*",$unpacked_node);
    $node =~s/$self->{'node_separator'}/\//g;
    $node =~ s/\/\.\./\//g;
    $node =~ s/\.\.\//\//g;
    my $rootdir="/".join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my $contents='';
    if(-f "$rootdir/$node"){ 
        my $fh = FileHandle->new;
        if ($fh->open("< $rootdir/$node")) {
            while(my $line=<$fh>){
                $contents.=$line;
            }
            $fh->close;
            print STDERR "exit contents with contents\n" if $self->{'trace'};
            return $contents;
        }
    }else{
        print STDERR "exit contents no\n" if $self->{'trace'};
        return "no.";
    }
    print STDERR "exit contents undef\n" if $self->{'trace'};
    return undef;
}

sub openssl_cnf_template{
    my ($self)=shift;
    print STDERR "enter openssl_cnf_template\n" if $self->{'trace'};
    my $the_template = <<_END_TEMPLATE_;
HOME = [\% cert_home_dir \%]
RANDFILE = \$HOME/.rnd
ca-domain = [\% ca_domain \%]
 
[ ca ]
default_ca = CA_default # The default ca section

[ CA_default ]
dir = \${HOME}
certs = \$dir/certs
crl_dir = \$dir/crl
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/pem
serial = \$dir/serial
crlnumber = \$dir/crlnumber
crl = \$dir/crl
private_key = \$dir/private/key
RANDFILE = \$dir/private/.rand
x509_extensions = usr_cert
name_opt = ca_default
cert_opt = ca_default
default_days = [\% ca_default_days \%]
default_crl_days= [\% crl_days \%]
default_md = sha1
preserve = no
policy = policy_match
 
[ policy_match ]
organizationName = optional
organizationalUnitName = optional
commonName = optional
userId = optional
emailAddress = optional
 
[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional
 
[ req ]
default_bits = 1024
default_keyfile = pem
distinguished_name = req_distinguished_name
attributes = req_attributes
x509_extensions = v3_ca
 
[ req_distinguished_name ]
[\% req_distinguished_name \%]
 
[ req_attributes ]
challengePassword = A challenge password
challengePassword_min = 4
challengePassword_max = 20
 
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
nsCaRevocationUrl = [\% crl_path \%]
 
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
nsCaRevocationUrl = [\% crl_path \%]
 
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
nsCaRevocationUrl = [\% crl_path \%]
_END_TEMPLATE_

    print STDERR "exit openssl_cnf_template\n" if $self->{'trace'};
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
