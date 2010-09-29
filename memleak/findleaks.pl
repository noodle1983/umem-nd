#!/usr/local/bin/perl
use IPC::Open2;
use IPC::Open3;
use Symbol;
use IO::Handle;
use IO::Select;

#debug level
my $DEBUG_GDBRSP = 0x1;
my $DEBUG_GDBCMD = 0x2;
my $DEBUG_CACHE = 0x4;
my $DEBUG_WALKER = 0x8;
my $DEBUG_FILL = 0x10;
my $DEBUG_IGNORE = 0x20;
my $DEBUG_FUN = 0x40;

my $global_debug = 0;

#console parameter
my $exec_name = shift | "a.out";
my $core_file = shift | "core";

#global attribute
my $selector = IO::Select->new();
my $gdb_cmd = "gdb $exec_name $core_file";
my $GDB_PROMT = "(gdb)";
my @res;

my $GDB_OUT = gensym();
my $GDB_IN = gensym();
my $GDB_ERR = gensym();

#a pipe to gdb and ignore the promt messages.
eval{ my $gdb_pid = open3 ($GDB_IN, $GDB_OUT, $GDB_ERR, "$gdb_cmd");};
$selector->add($GDB_OUT);
getOutputFrom();

my $total_size = 0;
#walk_umem_cache(leaky_estimate, \$total_size);
#walk_vmem(callback_walk_vmem_test, \$total_size);

my @ltab;
leaky_subr_fill(\@ltab, 0x10);
#walk_vmem_alloc( leaky_seg,	"0xb7f29280", \@ltab);

print doGdbCmd("quit");
close $GDB_OUT;
close $GDB_IN;
waitpid($gdb_pid, 0);
print "\nDone\n";

#---------------------------------------------------------------
#command logic
#---------------------------------------------------------------
sub leaky_subr_fill
{
	my $ltab = shift;
	my $debug = shift || $global_debug;

	print "[leaky_subr_fill]\n" if ($debug & $DEBUG_FUN);

	#walk_vmem(leaky_vmem, $ltab, $debug);

	walk_umem_cache(leaky_cache, $ltab, $debug);
}
#---------------------------------------------------------------
sub leaky_vmem
{
	my $cache_addr = shift;
	my $data = shift;
	my $debug = shift || $global_debug;
	print "[leaky_vmem]\n" if ($debug & $DEBUG_FUN);

	my $vm_name = 
		getAttribByAddr("(vmem_t*)", "$cache_addr", "vm_name", $debug);
	die "[leaky_vmem] fatal error: ((vmem_t*)$cache_addr)->vm_name is empty:[$vm_name]" 
		if $vm_name =~ m/^\s*$/;

	if ($vm_name ne "umem_oversize" && $vm_name ne "umem_memalign")	
	{
		print "[leaky_vmem] ignore vmem. vm_addr:$cache_addr, vm_name:$vm_name\n" if ($debug & $DEBUG_IGNORE);
		return undef;
	}

	walk_vmem_alloc(leaky_seg, $cache_addr, $data, $debug);

}
#---------------------------------------------------------------
sub leaky_seg{
	my $seg_addr = shift;
	my $vstype_vmaddr_data = shift;
	my $debug = shift ||$global_debug;

	my $vs_type = $vstype_vmaddr_data->[0];
	my $vm_addr = $vstype_vmaddr_data->[1];
	my $data = $vstype_vmaddr_data->[2];

	my ($type, $seg_vs_type) = 
		getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_type");

	if ($seg_vs_type ne "0" && $seg_vs_type ne "$vs_type")
	{
		print "[leaky_seg] ignore seg. ((vmem_t*)$vm_addr)->vm_seg0.vs_type = $seg_vs_type\n" 
			if ($debug & $DEBUG_IGNORE);
		return undef;
	}

	my ($type, $seg_vs_start) = 
		getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_start");
	my ($type, $seg_vs_end) = 
		getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_end");
	
	my $lkm_ctl_addr = hex(substr $seg_addr, 2);
	$lkm_ctl_addr = (($lkm_ctl_addr & ~3) | 1);
	$lkm_ctl_addr = sprintf "0x%x", $lkm_ctl_addr;

	print "[leaky_seg]start:$seg_vs_start, end:$seg_vs_end, addr:$lkm_ctl_addr, ((vmem_seg_t*)$seg_addr)\n" if $debug & $DEBUG_FILL;
	push @$data, [$seg_vs_start, $seg_vs_end, $lkm_ctl_addr];

}
#---------------------------------------------------------------
sub leaky_cache
{
	my $cache_addr = shift;
	my $data = shift;
	my $debug = shift ||$global_debug;

	if (not leaky_interested($cache_addr))
	{
		return undef;
	}

	my ($type, $cache_flags) = 
		getAttribByAddr("(umem_cache_t *)", "$cache_addr", "cache_flags", $debug);

	my $audit = $cache_flags & 0x1;
	if ($audit)
	{
		print "[leaky_cache]((umem_cache_t *)$cache_addr)->cache_flags:$cache_flags\n";
		#walk = "bufctl";
		#cb = (mdb_walk_cb_t)leaky_mtab;
	}
	else
	{
		#walk = "umem";
		#cb = (mdb_walk_cb_t)leaky_mtab_addr;
	}



}
#---------------------------------------------------------------
#---------------------------------------------------------------
sub walk_vmem{
	my $callback = shift;	
	my $data = shift;
	my $debug = shift ||$global_debug;

	print "[walk_vmem]\n" if ($debug & $DEBUG_FUN);
	walk("(vmem_t *)", "vmem_list", "vm_next", $callback, $data, undef, $debug);
}

sub callback_walk_vmem_test{
	my $cache_addr = shift;
	my $data = shift;

	print "[callback_walk_vmem_test]((vmem_t *)$cache_addr)\n";
}

#---------------------------------------------------------------
sub walk_vmem_alloc{
	my $callback = shift;	
	my $vm_addr = shift;
	my $data = shift;
	my $debug = shift ||$global_debug;
	print "[walk_vmem_alloc]\n" if ($debug & $DEBUG_FUN);

	walk_vmem_seg($callback, ["1", $vm_addr, $data], $debug);

}
#---------------------------------------------------------------
sub walk_vmem_seg{
	my $callback = shift;	
	my $vstype_vmaddr_data = shift;
	my $vm_addr = $vstype_vmaddr_data->[1];
	my $debug = shift ||$global_debug;

	my ($addr_type, $addr_of_vs_header) = 
		getAddrByCmd("print &((vmem_t*)$vm_addr)->vm_seg0");
	walk("$addr_type", "vmem_seg", "vs_anext", 
		$callback, $vstype_vmaddr_data, $addr_of_vs_header, $debug);
}

sub callback_vs_test{
	my $seg_addr = shift;
	my $vstype_vmaddr_data = shift;
	my $debug = shift ||$global_debug;

	my $vs_type = $vstype_vmaddr_data->[0];
	my $vm_addr = $vstype_vmaddr_data->[1];
	my $data = $vstype_vmaddr_data->[2];

	my ($type, $value) = getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_type");

	print "seg_addr:$seg_addr, wvs_type:$vs_type, svs_type:$value, data:$data\n";

}

#---------------------------------------------------------------
sub walk_umem_cache{
	my $callback = shift;	
	my $data = shift;
	my $debug = shift ||$global_debug;

	walk("(umem_cache_t *)", "&umem_null_cache", "cache_next", 
		$callback, $data, undef, $debug);
}
#---------------------------------------------------------------
sub leaky_interested{
	my $cache_addr = shift;
	my $debug = shift ||$global_debug;

	my ($vmem_type, $vmem_value) = 
		getAttribByAddr("(umem_cache_t*)", "$cache_addr", "cache_arena");

	die "[leaky_estimate] fatal error: cannot read arena for cache $cache_addr" 
		if (not $vmem_value) ;
	if ($vmem_value eq "0x0")
	{
		print "[leaky_interested]ignore umem_cache's vmemt. cache_addr:$cache_addr, vmem_addr:$vmem_value\n" if ($debug & $DEBUG_IGNORE); 
		return 0;
	}

	my ($type, $vm_name) =
		getAttribByAddr("$vmem_type", "$vmem_value", "vm_name", 0);	
	die "[leaky_estimate] fatal error: vm_name is empty" 
		if $vm_name =~ m/^\s*$/;

	if ($vm_name ne "umem_default" 
		&& $vm_name ne "umem_firewall")
	{
		print "[leaky_interested]ignore umem_cache's vmemt. cache_addr:$cache_addr, vmem_addr:$vmem_value, vm_name:$vm_name\n" if ($debug & $DEBUG_IGNORE); 
		return 0;
	}
	return 1;

}
#---------------------------------------------------------------
sub leaky_estimate
{
	my $cache_addr = shift;
	my $data = shift;
	my $debug = shift ||$global_debug;
	
	my ($vmem_type, $vmem_value) = 
		getAttribByAddr("(umem_cache_t*)", "$cache_addr", "cache_arena");

	die "[leaky_estimate] fatal error: cannot read arena for cache $cache_addr" 
		if (not $vmem_value) ;
	return undef if $vmem_value eq "0x0"; 

	my ($type, $vm_name) =
		getAttribByAddr("$vmem_type", "$vmem_value", "vm_name", 0);	
	die "[leaky_estimate] fatal error: vm_name is empty" 
		if $vm_name =~ m/^\s*$/;

	$$data++;
	print "name:$vm_name, data:$$data\n";
#	if ($vm_name ne "umem_default" 
#		&& $vm_name ne "umem_firewall")
#	{
#		$$data += ;
#	}

}
#---------------------------------------------------------------
# general methods to communicate to gdb
#---------------------------------------------------------------
sub doGdbCmd{
	my $cmd = shift;
	my $debug = shift || $global_debug;
	#print "$cmd\n";
	print $GDB_IN "$cmd\n";
	my @res = getOutputFrom($debug);

	if ($debug & $DEBUG_GDBCMD)
	{
		print "="x60 . "\n";
		print "-"x60 . "\n";
		print "$GDB_PROMT $cmd\n";
		for (@res){print "$_\n";};
		print "-"x60 . "\n";
		print "="x60 . "\n";
	}

	#sometimes gdb just return nothing, I don't know why
	#a bug in gdb?
	#retry
	my $retry_time = 3;
	while ($cmd =~ m/print/ and $res[0] =~ m/^\s*$/ and $retry_time-- > 0)
	{
		sleep 1;
		print $GDB_IN "$cmd\n";
		@res = getOutputFrom($debug);
		if ($debug & $DEBUG_GDBCMD)
		{
			print "="x60 . "\n";
			print "-"x60 . "\n";
			print "$GDB_PROMT $cmd(retry)\n";
			for (@res){print "$_\n";};
			print "-"x60 . "\n";
			print "="x60 . "\n";
		}
	}

	die "[doGdbCmd] fatal error: empty response from gdb of cmd: $cmd\n" 
		if not @res and not $cmd =~ m/quit/i;

	return @res;
}

#---------------------------------------------------------------
#
sub getOutputFrom
{
	my $debug = shift || $global_debug;
	my @result;
	my $lines = '';
	my $offset = 0;
	my $empty_count = 0;
	while (1)
	{
		my @ready = $selector->can_read(0.1);
		if (not @ready)
		{
			$empty_count++;
			if ($empty_count > 100)
			{
				print "[getOutputFrom] no ouput message for ${$empty_count*0.1;}s.\n"
					if ($debug & $DEBUG_GDBRSP);
				last;
			}
			next;
		}

		$offset = sysread $ready[0], $lines, 256, $offset;
		if ($offset == 0)
		{
			print "[getOutputFrom] read nothing, gdb may quit. \n"
				if ($debug & $DEBUG_GDBRSP);
			last;
		}

		while ( $lines =~ m|(.*?)\n|g)
		{
			push @result, $1;
			$offset = pos($lines);
		}
		$lines = substr $lines, $offset;
		$offset = length($lines);

		last if $lines =~ m/^\(gdb\)/;
	}
	return @result;

}
#---------------------------------------------------------------
sub walk{
	my $cache_type = shift;
	my $cache_name = shift;
	my $next_attrib = shift;
	my $callback = shift;	
	my $data = shift;
	my $begin_addr = shift;
	my $debug = shift ||$global_debug;

	print "[walk]\n" if ($debug & $DEBUG_FUN);
	my $addr_of_cache_header = $begin_addr || getAddrBySymbol($cache_name, $debug);
	die "[walk] fatal error: can't get the addr of $cache_name!\n" 
		if not defined $addr_of_cache_header;

	my $addr_of_cur_cache = $addr_of_cache_header;	
	do {
		print "[walk] walk_$cache_name($addr_of_cur_cache)\n"
			if ($debug & $DEBUG_WALKER);
		&$callback($addr_of_cur_cache, $data, $debug);
		$addr_of_cur_cache = getNextCache($cache_type, $next_attrib, $addr_of_cur_cache, $debug);
	} while($addr_of_cur_cache ne $addr_of_cache_header 
		and $addr_of_cur_cache ne "0x0");

}
#---------------------------------------------------------------
sub getNextCache
{
	my $cache_type = shift;
	my $next_attrib = shift;
	my $current = shift; 
	my $debug = shift ||$global_debug;

	print "[getNextCache]($cache_type $current)->$next_attrib\n" if ($debug & $DEBUG_FUN);
    my ($type, $value) = 
		getAttribByAddr("$cache_type", "$current", "$next_attrib", $debug);	
	#print "type:$type value:$value\n";
	return $value;

}
#---------------------------------------------------------------
sub getAttribByAddr
{
	#type must with ()
	my $type = shift;
	my $addr = shift;
	my $attr_name = shift;
	my $debug = shift || $global_debug;
	our %addr_name_cache;

	if (defined $addr_name_cache{"$addr.$attr_name"})
	{
		my $rtype = $addr_name_cache{"$addr.$attr_name"}->[0];
		my $rvalue = $addr_name_cache{"$addr.$attr_name"}->[1];
		print "[getAttribByAddr] from cache ($rtype, $rvalue).\n"
			if ($debug & $DEBUG_CACHE);
		return ($rtype, $rvalue);
	}

	my @res = doGdbCmd("print ($type $addr)->$attr_name", $debug);

	if ($res[0] =~ m/^\$.* = (\(.+?\)) (0x\w+)$/ )
	{
		$addr_name_cache{"$addr.$attr_name"} = [$1, $2];
		return ($1, $2);
	}
	#string
	if ($res[0] =~ m/^\$.* = "(\S+)"/ )
	{
		$addr_name_cache{"$addr.$attr_name"} = [undef, $1];
		return (undef, $1);
	}
	#hex integer
	if ($res[0] =~ m/^\$.* = (\d+)( '.*'\s*$)?/ )
	{
		$addr_name_cache{"$addr.$attr_name"} = [undef, $1];
		return (undef, $1);
	}
	return undef;

}
#---------------------------------------------------------------
sub getAddrByCmd{
	my $cmd = shift;
	my $debug = shift||$global_debug;

	my @res = doGdbCmd("$cmd", $debug);
	if ($res[0] =~ m/^\$.* = (.+?) (\w+)$/ )
	{
		return ($1, $2);
	}
	return undef;


}
#---------------------------------------------------------------
sub getAddrBySymbol
{
	my $name = shift; 
	my $debug = shift||$global_debug;

	my @res = doGdbCmd("print $name", $debug);	
	if ($res[0] =~ m/^\$.* = (\(.+?\)) (0x\w+)$/ )
	{
		return $2;
	}
	#if ($addr[0] =~ m/^.* (\w*)\.\s*$/)
	#{
	#	return $1;
	#}
	return undef;
}

