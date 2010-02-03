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
    my ($self, $param)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    $rootdir=~s/^\///;
    my $time=time();
    if($param->{'ca-nickname'}){
        if( ! -d "$rootdir/$param->{'ca-nickname'}" ){
            mkdir("$rootdir/$param->{'ca-nickname'}",0700); 
            my $fh = FileHandle->new("> $rootdir/$param->{'ca-nickname'}/$param->{'ca-nickname'}.crt");
            if (defined $fh) {
               print $fh Data::Dumper->Dump([$param]);
               $fh->close;
               return "SUCCESS";
            }
        }
    }
    return "ERROR";
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
