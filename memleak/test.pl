print add(0x1, 0x2);

sub add{
	my $first = shift;
	my $second = shift || 7;
	return $first + $second;

}
