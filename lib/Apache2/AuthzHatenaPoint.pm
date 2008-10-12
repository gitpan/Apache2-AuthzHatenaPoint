package Apache2::AuthzHatenaPoint;
use strict;
use warnings;
use Apache2::RequestRec ();
use Apache2::Module;
use Apache2::CmdParms;
use Apache2::Access;
use Apache2::Const -compile => qw(
    OK OR_AUTHCFG TAKE2 HTTP_PAYMENT_REQUIRED Apache2::Const::HTTP_UNAUTHORIZED DECLINED
);

use Time::Piece;
use WWW::HatenaLogin;
use Web::Scraper;
use DB_File;
use vars qw($VERSION);
$VERSION = '0.02';


__PACKAGE__->init;

sub init {
    my $self = shift;
    my @directives = (
        {
            name => 'hatenapoint',
            req_override => Apache2::Const::OR_AUTHCFG,
            args_how => Apache2::Const::TAKE2,
        },
    );

    eval {
        Apache2::Module::add($self, \@directives);
        Apache2::ServerUtil->server->push_handlers(
            PerlAuthzHandler => $self,
        );
    };
}

sub hatenapoint {
    my ($self, $parms, $arg1, $arg2) = @_;
    my $class = ref $self;
    my $s = $parms->server;
    my $i = Apache2::Module::get_config($class, $s);
    if ($arg1 eq 'after') {
        my $time = Time::Piece->strptime($arg2, '%Y-%m-%d') or die;
        $i->{$arg1} = $time;
    } elsif ($arg1 eq 'username' || $arg1 eq 'password' || $arg1 eq 'sentuserdb') {
        $i->{$arg1} = $arg2;
    }
}

sub handler : method {
    my ($self, $r) = @_;
    my %require =  map { my ($k, $v) = split /\s+/, $_->{requirement}, 2; ($k, $v || '')}
        @{ $r->requires };
    my $needpoint = $require{hatenapoint} or return Apache2::Const::DECLINED;
    my $username = $r->user or return Apache2::Const::HTTP_UNAUTHORIZED;
    $username =~ s{^www.hatena.ne.jp/}{} or return Apache2::Const::HTTP_UNAUTHORIZED;
    $self->set_custom_response($r, $needpoint);
    my $cf = Apache2::Module::get_config($self, $r->server);
    $cf->{needpoint} = $needpoint;
    return $self->check_username($cf, $username);
}

sub check_username {
    my ($self, $cf, $username) = @_;
    $username eq $cf->{username} and return Apache2::Const::OK;
    my %sentuser = ();
    if (my $dbfile = $cf->{sentuserdb}) {
        tie %sentuser, 'DB_File', $dbfile;
        return Apache2::Const::OK if exists $sentuser{$username};
    }
    %sentuser = (%sentuser, $self->scrape($cf));
    return exists $sentuser{$username} ?
        Apache2::Const::OK : Apache2::Const::HTTP_PAYMENT_REQUIRED;
}

sub scrape {
    my ($self, $cf) = @_;
    my $session = WWW::HatenaLogin->new({
            username => $cf->{username},
            password => $cf->{password},
        }) or die;
    my $scraper = scraper {
        process "table.accounttable>tbody>tr",
            'lines[]' => scraper {
                process 'td:nth-child(1)', 'date' => 'TEXT';
                process 'td:nth-child(2) a', 'from' => 'TEXT';
                process 'td:nth-child(3) b', 'ammount' => 'TEXT';
            };
        result 'lines';
    };
    $scraper->user_agent->cookie_jar($session->cookie_jar);
    my $res = $scraper->scrape(URI->new("http://www.hatena.ne.jp/history"));
    return map {($_->{from},$_->{ammount})}
           grep {
               defined $_->{date} && 
               defined $_->{ammount} && 
               defined $_->{from} &&
               $_->{ammount} >= $cf->{needpoint} && 
               Time::Piece->strptime($_->{date}, "%Y/%m/%d") >= $cf->{after}
           } @{$res};
}

sub set_custom_response {
    my ($self, $r, $needpoint) = @_;
    (my $user = $r->user) =~ s{^www.hatena.ne.jp/}{};
    my $cf = Apache2::Module::get_config($self, $r->server);
    my $html = <<END;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html lang="en">
    <head>
        <title>402 Payment Required</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <meta http-equiv="Content-Style-Type" content="text/css">
        <style type="text/css"><!--
            body {
                color: #666;
                background-color: #fff9f9;
                margin: 100px;
                padding: 20px;
                border: 2px solid #aaa;
                font-family: "Lucida Grande", verdana, sans-serif;
                line-height: 1.5em;
            }
            --></style>
    </head>
    <body>
        <h1>Please send hatena point.</h1>
            <p>
            Hi id:$user! Please <a href="http://www.hatena.ne.jp/sendpoint?name=$cf->{username}&price=$needpoint">send $needpoint hatena point to id:$cf->{username}</a> and come back.
            </p>
    </body>
</html>
END
    $r->custom_response(
        Apache2::Const::HTTP_PAYMENT_REQUIRED,
        $html,
    );
}

1;
__END__

=head1 NAME

Apache2::AuthzHatenaPoint - a module to authorize http clients with hatena point.

=head1 SYNOPSIS

  LoadModule perl_module modules/mod_perl.so
  PerlLoadModule Apache2::AuthenOpenID
  PerlLoadModule Apache2::AuthzHatenaPoint

  AuthType          OpenID
  AuthName          "My private documents"
  return_to         http://sample.com/path/to/callback
  trust_root        http://sample.com/your/trust_root/
  consumer_secret   "your consumer secret"
  require           hatenapoint 10000
  hatenapoint       username    your_username
  hatenapoint       password    your_password
  hatenapoint       after       2008-03-28
  hatenapoint       sentuserdb  /path/to/.htsentuserdb

=head1 DESCRIPTION

Apache2::AuthzHatenaPoint is a module to authorize http client with hatena point.

=head1 AUTHOR

Author E<lt>nobuo.danjou@gmail.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<Apache2::AuthenOpenID>
L<http://openid.net>
L<http://www.hatena.ne.jp>

=cut
