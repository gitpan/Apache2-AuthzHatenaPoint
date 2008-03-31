use strict;
use warnings;
use ExtUtils::MakeMaker;
use Apache::TestMM qw(test clean);

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
    'NAME'      => 'Apache2::AuthzHatenaPoint',
    'VERSION_FROM' => 'lib/Apache2/AuthzHatenaPoint.pm', # finds $VERSION
    'PREREQ_PM' => {
	    'Test::More' => 0.32,
        'mod_perl2'  => 2.000001,
        'Apache::Test' => 0,
        'Apache2::AuthenOpenID' => 0,
        'Web::Scraper' => 0,
        'WWW::HatenaLogin' => 0,
        'Time::Piece' => 0,
    },
);
