#!/usr/local/bin/perl
use IPC::Open2;
use IPC::Open3;
use Symbol;
use IO::Handle;
use IO::Select;
use Data::Dumper;

#debug level
my $DEBUG_GDBRSP = 0x1;
my $DEBUG_GDBCMD = 0x2;
my $DEBUG_CACHE = 0x4;
my $DEBUG_WALKER = 0x8;
my $DEBUG_FILL = 0x10;
my $DEBUG_IGNORE = 0x20;
my $DEBUG_FUN = 0x40;
my $DEBUG_DUMP = 0x80;

my $DEBUG_LOGIC = $DEBUG_FILL | $DEBUG_IGNORE | $DEBUG_DUMP;
my $global_debug = 0;

#console parameter
my $exec_name = shift || "a.out";
my $core_file = shift || "core";

#global attribute
my $selector = IO::Select->new();
my $gdb_cmd = "gdb --interpreter=mi -q $exec_name $core_file";
my $GDB_PROMT = "\\(gdb\\)";
my @res;

my $GDB_OUT = gensym();
my $GDB_IN = gensym();
my $GDB_ERR = gensym();

#a pipe to gdb and ignore the promt messages.
eval{ my $gdb_pid = open3 ($GDB_IN, $GDB_OUT, $GDB_ERR, "$gdb_cmd");};
$selector->add($GDB_OUT);
sleep 1;
getOutputFrom(-1);
doGdbCmd("-stack-info-frame");

#func test
#print doGdbCmd("-data-evaluate-expression \"umem_null_cache.cache_next\"", $DEBUG_GDBCMD) . "\n";
#print getAddrBySymbol("&umem_null_cache") . "\n";
#print getAttribByAddr("(umem_cache_t*)", "0xb7fd0e20", "cache_next") . "\n";
#my $total_size = 0;
#walk_umem_cache(leaky_estimate, \$total_size);
#walk_vmem(callback_walk_vmem_test, \$total_size);

#table:[[vs_start_str, vs_start_int, vs_end_str, vs_end_int, bufctl, seg_type]]
my @ltab;
leaky_subr_fill(\@ltab, 0);
@ltab = sort {$a->[1]<=>$b->[1]} @ltab;
#print "actual buffers[[vs_start, vs_end, bufctl]]:\n" 
#	. Data::Dumper->Dump(\@ltab); #if $global_debug & $DEBUG_DUMP;

#leaky_subr_run();
walk_thread(\@ltab, 0);
print "actual buffers[[vs_start_str, vs_start_int, vs_end_str, vs_end_int, bufctl, seg_type]]:\n" 
	. Data::Dumper->Dump(\@ltab) if $global_debug & $DEBUG_DUMP;
#walk_section();
#info variables


my $LK_BUFCTLHSIZE = 127;
my %lk_bufctl;
find_leak(\@ltab);
#leaky_dump();

doGdbCmd("-gdb-exit");
close $GDB_OUT;
close $GDB_IN;
waitpid($gdb_pid, 0);
print "\nDone\n";

#---------------------------------------------------------------
#command logic
#---------------------------------------------------------------
sub leaky_dump{
	my $debug = shift || $global_debug;
	print "[leaky_dump]\n" if ($debug & $DEBUG_FUN);

	printf "\n\n%5s %18s %18s %s\n", "COUNT", "CACHE", "BUFCTL", "CALLER";
	while (my ($k, $v) = each %lk_bufctl)
	{
		#[1, $type, $bufctl_addr, $buf_addr, $timestamp, 
		#	$stack, $depth, $cid, $data];
		printf "%5s %18s %18s %s\n"
			, $v->[0], $v->[3], $v->[2], disass_addr($v->[5]->[0], $debug);
		if ($v->[6] > 1)
		{
			for (1..($v->[6]-1))
			{
				printf "%43s %s\n" , "",disass_addr($v->[5]->[$_], $debug);
			}
		}
		print "\n";
	}

}
#---------------------------------------------------------------
sub disass_addr{
	my $addr = shift; 
	my $debug = shift||$global_debug;

	if (not $addr =~ /^0x/)
	{
		$addr = sprintf "0x%x", $addr;
	}
	my $func_name = disass_func($addr,$debug);
	my $src_file = disass_src($addr, $debug);
	return sprintf "%-10s %s %s", $addr, $func_name, $src_file;
}
#---------------------------------------------------------------
sub disass_addr_direct{
	my $addr = shift; 
	my $debug = shift||$global_debug;

	if (not $addr =~ /^0x/)
	{
		$addr = sprintf "0x%x", $addr;
	}

	my @res = doGdbCmd("-data-disassemble -s $addr -e $addr+8 1", $debug);	
	my $lines;
	if ($res[0] =~ m/^\^done,asm_insns=\[(.*)\]/ )
	{
		$lines = $1;
	}

	my $src_line, my $src_file, my $insn_addr;
	my $func_name, my $offset;
	if ($lines =~ m|line=\"(\d+)\"|)
	{
		$src_line = $1;	
	}

	if ($lines =~ m|file=\"([^"]+)\"|)
	{
		$src_file = $1;	
	}

	if ($lines =~ m|address=\"([^"]+)\"|)
	{
		$insn_addr = $1;	
	}

	if ($lines =~ m|func-name=\"([^"]+)\"|)
	{
		$func_name = $1;	
	}
	
	if ($lines =~ m|offset=\"([^"]+)\"|)
	{
		$offset = $1;	
	}

	if ($src_file && $src_line)
	{
		return "$insn_addr $func_name+$offset $src_file:$src_line";
	}
	elsif ($insn_addr)
	{
		return "$insn_addr $func_name+$offset";
	}
	return "$addr  ?:?";
}
#---------------------------------------------------------------
sub find_leak{
	my $ltab = shift;
	my $debug = shift || $global_debug;
	print "[find_leak]\n" if ($debug & $DEBUG_FUN);

	undef %lk_bufctl;
	foreach my $buff (@$ltab)
	{
		if (not $buff->[1] & 1)
		{
			leaky_subr_add_leak($buff, $debug);

		}
	}
}
#---------------------------------------------------------------
sub leaky_subr_add_leak{
	my $leak_buff = shift;
	my $debug = shift || $global_debug;
	print "[leaky_subr_add_leak]\n" if ($debug & $DEBUG_FUN);

	my $depth = 0;
	my $timestamp = 0;
	my @stack;
	my $cid;
	my $data;
	#LKM_CTL_BUFCTL
	if ($leak_buff->[5] == 0)
	{
		$depth = 
			getAttribByAddr("(umem_bufctl_audit_t*)", "$leak_buff->[4]", "bc_depth", $debug);
		return if $depth < 1;
		$timestamp = 
			getAttribByAddr("(umem_bufctl_audit_t*)", "$leak_buff->[4]", "bc_timestamp", $debug);
		for (1..($depth - 1))
		{
			my $cur_stack = getAttribByAddr("(umem_bufctl_audit_t*)", "$leak_buff->[4]", "bc_stack[$_]", $debug);
			push @stack, $cur_stack;
		}
		$depth -= 1;
		$cid = getAttribByAddr("(umem_bufctl_audit_t*)", "$leak_buff->[4]", "bc_cache", $debug);
		$data = $cid;
	}
	#LKM_CTL_VMSEG
	elsif ($leak_buff->[5] == 1)
	{
		$depth = getAttribByAddr("(vmem_seg_t*)", "$leak_buff->[4]", "vs_depth", $debug);
		return if $depth < 1;
		$timestamp = getAttribByAddr("(vmem_seg_t*)", "$leak_buff->[4]", "vs_timestamp", $debug);
		for (1..($depth - 1))
		{
			my $cur_stack = getAttribByAddr("(vmem_seg_t*)", "$leak_buff->[4]", "vs_stack[$_]", $debug);
			push @stack, $cur_stack;
		}
		$depth -= 1;
		$data = $leak_buff[3] - $leak_buff[1];
	}
	else
	{
		die "[leaky_subr_add_leak]fatal error: unsupport buffer type:$leak_buff->[5]\n"; 
	}

	print "add stack:\n" 
		. Data::Dumper->Dump(\@stack) if $debug & $DEBUG_DUMP;
	leaky_add_leak($leak_buff->[5], $leak_buff->[4], $leak_buff->[0]
					, $timestamp, \@stack, $depth
					, $cid, $data, $debug);
}

#---------------------------------------------------------------
sub leaky_add_leak{
	my $type = shift;
	my $bufctl_addr = shift;
	my $buf_addr = shift;
	my $timestamp = shift;
	my $stack = shift;
	my $depth = shift;
	my $cid = shift;
	my $data = shift;
	my $debug = shift || $global_debug;
	print "[leaky_add_leak]\n" if ($debug & $DEBUG_FUN);

	my $total = $type;
	for (@$stack)
	{
		$total ^= $_;
	}
	
	my $ndx = $total & $LK_BUFCTLHSIZE;
	my $no_match = 0;
	for (0 .. $LK_BUFCTLHSIZE)
	{
		if (not defined $lk_bufctl{$ndx})
		{
			print "[leaky_add_leak]add leak at index:$ndx\n" 
				if ($debug & $DEBUG_FILL);
			$lk_bufctl{$ndx} = [1, $type, $bufctl_addr, $buf_addr, $timestamp, 
								$stack, $depth, $cid, $data];

		}
		elsif ($type != $lk_bufctl{$ndx}->[1] 
				|| $depth != $lk_bufctl{$ndx}->[6]
				|| $cid != $lk_bufctl{$ndx}->[7])
		{
			$no_match = 1;
		}
		else
		{
			for (0..($depth-1))
			{
				next if $stack->[$_] == $lk_bufctl{$ndx}->[5]->[$_];
				$no_match = 1;
			}
			if ($no_match == 0)
			{
				print "[leaky_add_leak]dup leak at index:$ndx\n" 
					if ($debug & $DEBUG_FILL);
				$lk_bufctl{$ndx}->[0] += 1;
			}
				
		}

		$ndx = ($ndx + 1) & $LK_BUFCTLHSIZE if $no_match;
		last;
	}
	
}
#---------------------------------------------------------------
sub walk_thread{
	my $data = shift;
	my $callback = shift;
	my $debug = shift || $global_debug;
	print "[walk_thread]\n" if ($debug & $DEBUG_FUN);
	
	my @res = doGdbCmd("-thread-list-ids", $debug);
	while (@res[0] =~ /thread-id="(\d*)"/g)
	{
		my $tid = $1;
		walk_thread_frame($tid, $data, $callback, $debug);
	}
	
}
#---------------------------------------------------------------
sub walk_thread_frame{
	my $tid  = shift;
	my $data = shift;
	my $callback = shift;
	my $debug = shift || $global_debug;
	print "[walk_thread_frame]\n" if ($debug & $DEBUG_FUN);

	doGdbCmd("-thread-select $tid", $debug);

	my $stack_depth = -1;
	my @res = doGdbCmd("-stack-info-depth", $debug);
	if (@res[0] =~ /depth="(\d*)"/g)
	{
		$stack_depth = $1;
	}

	my $frame_index = 0;
	for (; $frame_index < $stack_depth; $frame_index++)
	{
		doGdbCmd("-stack-select-frame $frame_index", $debug);
		#my @res = doGdbCmd("-stack-list-locals --simple-values", $debug);
		#doGdbCmd("-data-evaluate-expression $name", $debug);
		my @res = doGdbCmd("-stack-list-locals --all-values", $debug);
		while (@res[0] =~ /(0x[0-9a-f]+)/g)
		{
			leaky_do_grep_ptr($1, $data, $debug);
		}
		
		walk_thread_frame_variabale($data, $callback, $debug);	
	}
	
	#&$callback($tid, $data, $debug);
}
#---------------------------------------------------------------
sub walk_thread_frame_variabale{
	my $data = shift;
	my $callback = shift;
	my $debug = shift || $global_debug;
	print "[walk_thread_frame_variabale]\n" if ($debug & $DEBUG_FUN);

	my @res = doGdbCmd("-stack-list-locals --simple-values", $debug);
	my @vars = split /\{|\}/, $res[0]; 
	my $var;
	for $var (@vars)
	{
		next if not $var =~ m/name="([^"]+)"/;
		my $name = $1;
		next if not $var =~ m/type="([^"]+)"/;
		my $type = $1;	
		my $value;
		if ($var =~ m/value="(.*)"/)
		{
			$value = $1;
		}
		
		print "name: $name, type: $type, value:$value\n";
		if ($type =~ m/^std::list/)
		{
			walk_std_list($name, $type, $data, $callback, -1); 
			next;
		}

	}
	doGdbCmd("-data-evaluate-expression $name", $debug);
}
#---------------------------------------------------------------
sub walk_var{
	my $name = shift;
	my $type = shift;
	my $value = shift;
	my $data = shift;
	my $callback = shift;
	my $debug = shift || $global_debug;
	print "[walk_var]\n" if ($debug & $DEBUG_FUN);

	if ($type =~ /\*/)
	{
		if ($value)
		{
			if (leaky_do_grep_ptr($current, $data, $debug) > 0)
			{
				print "found buffer: $current\n";
			}
		}
		print "[walk_var] ignore var:$type $name, value is empty\n" if $debug & $DEBUG_IGNORE;

	}
}
#---------------------------------------------------------------
sub walk_std_list{
	my $list_name = shift;
	my $list_type = shift;
	my $data = shift;
	my $callback = shift;
	my $debug = shift || $global_debug;
	print "[walk_std_list]\n" if ($debug & $DEBUG_FUN);

	my $node_type = (split ',',$list_type)[0]; 

	my $header = getAddrByCmd("-data-evaluate-expression &$list_name._M_impl._M_node", $debug);
	doGdbCLICmd("set \$current = $list_name._M_impl._M_node._M_next", $debug);
	my $current = getAddrByCmd("-data-evaluate-expression \$current", $debug);
	while($header ne $current)
	{
		if (leaky_do_grep_ptr($current, $data, $debug) > 0)
		{
			print "found buffer: $current\n";
		}
		#get the node value
		my $node_addr = getAddrByCmd("-data-evaluate-expression (\$current+1)", $debug);
		if ($node_type =~ /\*/)
		{
			my $node = getAddrByCmd("-data-evaluate-expression *($node_type*)(\$current+1)", $debug) 
		}
		else
		{

		}

		doGdbCLICmd("set \$current = \$current._M_next", $debug);
		$current = getAddrByCmd("-data-evaluate-expression \$current", $debug);
	}
}
#---------------------------------------------------------------
#return 
#0: not found
#1: found 1st time
#2: found more then 1 time
sub leaky_do_grep_ptr{
	my $addr = shift;
	my $ltab = shift;
	my $debug = shift || $global_debug;

	$addr = hex(substr $addr, 2) if $addr =~ /^0x/; 
	if ($addr < $ltab->[0]->[1] or
		$addr >= $ltab->[-1]->[3])
	{
		print "[leaky_do_grep_ptr] addr: $addr not in [$ltab->[0]->[1], $ltab->[-1]->[3])\n" if $debug & $DEBUG_IGNORE;
		return 0;
	}

	my $index = leaky_search($addr, $ltab, $debug);
	if ($index == -1)
	{
		print "[leaky_do_grep_ptr]not found addr: $addr \n" if $debug & $DEBUG_IGNORE;
		return 0;
	}

	my $buff = $ltab->[$index];
	if ($buff->[1] | 1)
	{
		print "[leaky_do_grep_ptr]dup addr: $addr \n" if $debug & $DEBUG_FILL;
		return 2;
	}
	$buff->[1] |= 1;
	print "[leaky_do_grep_ptr]found addr: $addr \n" if $debug & $DEBUG_FILL;
	return 1;

}
#---------------------------------------------------------------
sub leaky_search{
	my $addr = shift;
	my $ltab = shift;
	my $debug = shift || $global_debug;

	my $left = 0; 
	my $right = @$ltab - 1;
	my $guess;

	while ($left <= $right)
	{
		$guess = ($left + $right) >> 1;

		if ($addr < $ltab->[$guess]->[1])
		{
			$right = $guess -1;
			#print "guess:$guess, [$left, $right)\n";
			next;
		}

		if ($addr >= $ltab->[$guess]->[3])
		{
			$left = $guess +1;
			#print "guess:$guess, [$left, $right)\n";
			next;
		}
		return $guess;
	}
	return -1;
}
#---------------------------------------------------------------
sub leaky_subr_fill{
	my $ltab = shift;
	my $debug = shift || $global_debug;

	print "[leaky_subr_fill]\n" if ($debug & $DEBUG_FUN);

	walk_vmem(leaky_vmem, $ltab, $debug);

	walk_umem_cache(leaky_cache, $ltab, $debug);
}
#---------------------------------------------------------------
sub leaky_vmem
{
	my $cache_addr = shift;
	my $data = shift;
	my $debug = shift || $global_debug;
	print "[leaky_vmem]\n" if ($debug & $DEBUG_FUN);

	my $vm_name = getAttribByAddr("(vmem_t*)", "$cache_addr", "vm_name", $debug);
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
	print "[leaky_seg]\n" if ($debug & $DEBUG_FUN);

	my $vs_type = $vstype_vmaddr_data->[0];
	my $vm_addr = $vstype_vmaddr_data->[1];
	my $data = $vstype_vmaddr_data->[2];

	my $seg_vs_type = getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_type");

	if ($seg_vs_type ne "0" && $seg_vs_type ne "$vs_type")
	{
		print "[leaky_seg] ignore seg. ((vmem_t*)$vm_addr)->vm_seg0.vs_type = $seg_vs_type\n" 
			if ($debug & $DEBUG_IGNORE);
		return undef;
	}

	my $seg_vs_start = getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_start");
	my $seg_vs_start_str = sprintf "0x%x", $seg_vs_start;
	my $seg_vs_end = getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_end");
	my $seg_vs_end_str = sprintf "0x%x", $seg_vs_end;
	
	#mark it LKM_CTL_VMSEG(1)
	my $seg_type = 1;

	print "[leaky_seg]start:$seg_vs_start, end:$seg_vs_end, addr:$lkm_ctl_addr, ((vmem_seg_t*)$seg_addr)\n" if $debug & $DEBUG_FILL;
	push @$data, [$seg_vs_start_str, $seg_vs_start, 
				  $seg_vs_end_str, $seg_vs_end, 
				  $seg_addr, $seg_type];
}
#---------------------------------------------------------------
##define	LKM_CTL_BUFCTL	0	/* normal allocation, PTR is bufctl */
##define	LKM_CTL_VMSEG	1	/* oversize allocation, PTR is vmem_seg_t */
##define	LKM_CTL_MEMORY	2	/* non-umem mmap or brk, PTR is region start */
##define	LKM_CTL_CACHE	3	/* normal alloc, non-debug, PTR is cache */
##define	LKM_CTL_MASK	3L
sub LKM_CTL{
	my $addr = shift;
	my $type = shift;

	my $lkm_ctl_addr = hex(substr $addr, 2);
	$lkm_ctl_addr = (($lkm_ctl_addr & ~3) | $type);
	return $lkm_ctl_addr;
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

	my $cache_flags = getAttribByAddr("(umem_cache_t *)", "$cache_addr", "cache_flags", $debug);
	my $cache_bufsize = getAttribByAddr("(umem_cache_t *)", "$cache_addr", "cache_bufsize", $debug);

	#transaction auditing.
	my $audit = $cache_flags & 0x1;
	if ($audit)
	{
		#print "[leaky_cache]((umem_cache_t *)$cache_addr)->cache_flags:$cache_flags\n";
		walk_umem_bufctl(leaky_mtab, $cache_addr, $data, $cache_flags, $debug);

	}
	else
	{
		die "[leaky_cache]fatal error, please set env like:\nUMEM_DEBUG=default\nUMEM_LOGGING=transaction\nLD_PRELOAD=/usr/local/lib/libumem.so:/usr/local/lib/libumem_malloc.so\nand try again, more info: ((umem_cache_t *)$cache_addr)->cache_flags:$cache_flags\n";
		#walk = "umem";
		#cb = (mdb_walk_cb_t)leaky_mtab_addr;
	}

	#fill the vc_end
	my $back_it = -1;
	while ($data->[$back_it]->[3] == -1)
	{
		$data->[$back_it]->[3] = $data->[$back_it]->[1] + $cache_bufsize;
		$data->[$back_it]->[2] = sprintf "0x%x", $data->[$back_it]->[3];
	}
}
#---------------------------------------------------------------
sub leaky_mtab{
	my $bufctl_addr = shift;
	my $data = shift;
	my $debug = shift ||$global_debug;
	print "[leaky_mtab]\n" if ($debug & $DEBUG_FUN);

	my $bc_addr = getAttribByAddr("(umem_bufctl_t *)", "$bufctl_addr", "bc_addr", $debug);      
	#mark it LKM_CTL_BUFCTL(0)
	my $seg_type = 0;

	print "[leaky_mtab]start:$bc_addr, end:unkown, addr:$lkm_ctl_addr\n" if $debug & $DEBUG_FILL;
	push @$data, [$bc_addr, hex(substr $bc_addr, 2), 
				  "", -1, 
				  $bufctl_addr, $seg_type];
}
#---------------------------------------------------------------
sub walk_umem_bufctl{
	my $callback = shift;	
	my $umem_addr = shift;
	my $data = shift;
	my $cache_flags = shift; 
	my $debug = shift ||$global_debug;
	print "[walk_umem_bufctl]\n" if ($debug & $DEBUG_FUN);

	#for bufctl, $type = UM_ALLOCATED(0x1) | UM_BUFCTL(0x4)
	##define	UM_ALLOCATED		0x1
	##define	UM_FREE			0x2
	##define	UM_BUFCTL		0x4
	##define	UM_HASH			0x8
	my $type = 5;

	#$type = $type & ~UMF_HASH(0x8)
	#no need

	my $cache_buftotal = 
		getAttribByAddr("(umem_cache_t *)", "$umem_addr", "cache_buftotal");
	if ($cache_buftotal == 0)
	{
		print "[walk_umem_bufctl]ignore umem bufctl. ((umem_cache_t *)$umem_addr)->cache_buftotal:$cache_buftotal\n" if ($debug & $DEBUG_IGNORE); 
		return;
	}
	
	#If they ask for bufctls, but it's a small-slab cache,there is nothing to report.
	#walk type contain UM_BUFCTL(0x4), but cache_flags without UMF_HASH(0x8), done
	if (($type & 0x4) && not ($cache_flags & 0x200)) 
	{
		print "[walk_umem_bufctl]ignore. bufctl, but no hash flags\n" if ($debug & $DEBUG_IGNORE); 
		return;
	}
	walk_umem_hash($callback, $umem_addr, $data, $debug);

}
#---------------------------------------------------------------
sub walk_umem_hash{
	my $callback = shift;	
	my $umem_addr = shift;
	my $data = shift;
	my $debug = shift ||$global_debug;
	print "[walk_umem_hash]\n" if ($debug & $DEBUG_FUN);

	my $cache_flags = getAttribByAddr("(umem_cache_t *)", "$umem_addr", "cache_flags", $debug);
	if (not ($cache_flags & 0x200)) 
	{
		print "[walk_umem_hash]ignore, no hash table. ((umem_cache_t *)$umem_addr)->cache_flags:$cache_flags\n" if ($debug & $DEBUG_IGNORE); 
		return;
	}

	my $cache_hash_table = getAttribByAddr("(umem_cache_t *)", "$umem_addr", "cache_hash_table", $debug);
	my $nelems = getAttribByAddr("(umem_cache_t *)", "$umem_addr", "cache_hash_mask", $debug) + 1;

	my $addr = "0x0";
	my $pos = 0;
	for (; $pos < $nelems; $pos++)
	{
		$addr = getAttribByAddr("(umem_cache_t *)", "$umem_addr", "cache_hash_table[$pos]", $debug);
		if ($addr eq "0x0")
		{
			print "[walk_umem_hash]ignore ((umem_cache_t *)$umem_addr)->cache_hash_table[$pos]:$addr\n" if ($debug & $DEBUG_IGNORE); 
			next;
		}
		while ($addr ne "0x0")
		{
			&$callback($addr, $data, $debug);
			$addr = getAttribByAddr("(umem_bufctl_t *)", "$addr", "bc_next", $debug);      
		}
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
	print "[walk_vmem_seg]\n" if ($debug & $DEBUG_FUN);

	my $addr_of_vs_header = getAddrByCmd("-data-evaluate-expression \"&((vmem_t*)$vm_addr)->vm_seg0\"");
	walk("(vmem_seg_t*)", "vmem_seg", "vs_anext", 
		$callback, $vstype_vmaddr_data, $addr_of_vs_header, $debug);
}

sub callback_vs_test{
	my $seg_addr = shift;
	my $vstype_vmaddr_data = shift;
	my $debug = shift ||$global_debug;

	my $vs_type = $vstype_vmaddr_data->[0];
	my $vm_addr = $vstype_vmaddr_data->[1];
	my $data = $vstype_vmaddr_data->[2];

	my $value = getAttribByAddr("(vmem_seg_t *)", "$seg_addr", "vs_type");

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

	my $vmem_value = getAttribByAddr("(umem_cache_t*)", "$cache_addr", "cache_arena");

	die "[leaky_interested] fatal error: cannot read arena for cache $cache_addr" 
		if (not $vmem_value) ;
	if ($vmem_value eq "0x0")
	{
		print "[leaky_interested]ignore umem_cache's vmemt. cache_addr:$cache_addr, vmem_addr:$vmem_value\n" if ($debug & $DEBUG_IGNORE); 
		return 0;
	}

	my $vm_name = getAttribByAddr("(vmem_t*)", "$vmem_value", "vm_name", 0);	
	die "[leaky_interested] fatal error: vm_name is empty" 
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
	
	my $vmem_value = getAttribByAddr("(umem_cache_t*)", "$cache_addr", "cache_arena");

	die "[leaky_estimate] fatal error: cannot read arena for cache $cache_addr" 
		if (not $vmem_value) ;
	return undef if $vmem_value eq "0x0"; 

	my $vm_name = getAttribByAddr("(vmem_t *)", "$vmem_value", "vm_name", 0);	
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

	print $GDB_IN "$cmd\n";
	my @res = getOutputFrom($debug);
	if ($debug & $DEBUG_GDBCMD)
	{
		print "="x60 . "\n";
		print "-"x60 . "\n";
		print "cmd:$cmd\n";
		for (@res){print "$_\n";};
		print "-"x60 . "\n";
		print "="x60 . "\n";
	}

	die "[doGdbCmd] fatal error: empty response from gdb of cmd: $cmd\n" 
		if not @res and not $cmd =~ m/quit/i;
	die "[doGdbCmd] fatal error: only 1 line is expected for mi interface!\ncmd:$cmd\nans:@res\n" 
		if @res > 1;
	die "[doGdbCmd]cmd error!\ncmd:$cmd\nans:@res\n" 
		if $res[0] =~ /^^done/;
	return $res[0];
}

#---------------------------------------------------------------
sub doGdbCLICmd{
	my $cmd = shift;
	my $debug = shift || $global_debug;

	print $GDB_IN "-interpreter-exec console \"$cmd\"\n";
	my @res = getOutputFrom($debug);
	if ($debug & $DEBUG_GDBCMD)
	{
		print "="x60 . "\n";
		print "-"x60 . "\n";
		print "cmd:-interpreter-exec console \"$cmd\"\n";
		for (@res){print "$_\n";};
		print "-"x60 . "\n";
		print "="x60 . "\n";
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
				die "[getOutputFrom]fatal error: no ouput message for 10s. or promt not found.\n"
					if ($debug & $DEBUG_GDBRSP);
			}
			next;
		}
		
		if( not sysread($ready[0], $lines, 2048, $offset))
		{
			print "[getOutputFrom] read nothing, gdb may quit. \n"
				if ($debug & $DEBUG_GDBRSP);
			last;
		}

		while ( $lines =~ m|(.*?)\n|g)
		{
			my $line = $1;
			last if $line =~ /^$GDB_PROMT/;
			next if $line =~ /^\s*$/;
			push @result, $line;
			$offset = pos($lines);
		}
		$lines = substr $lines, $offset;
		$offset = length($lines);

		last if $lines =~ m/^$GDB_PROMT/;
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
    my $next_addr = getAttribByAddr("$cache_type", "$current", "$next_attrib", $debug);	
	#print "type:$type value:$value\n";
	return $next_addr;

}
#---------------------------------------------------------------
sub getAttribByAddr
{
	#type must with ()
	my $type = shift;
	my $addr = shift;
	my $attr_name = shift;
	my $debug = shift || $global_debug;
	my $value;

	my @res = doGdbCmd("-data-evaluate-expression \"($type $addr)->$attr_name\"", $debug);
	if ($res[0] =~ m/^\^done,value=\"(.*)\"/ )
	{
		$value = $1;
	}

	#string
	if ($value =~ m/^\\\"(.*)\\\",/) 
	{
		$value = $1;
	}
	#int
	elsif ($value =~ m/^(\d+) '.*'/) 
	{
		$value = $1;
	}

	return $value;

}
#---------------------------------------------------------------
sub getAddrByCmd{
	my $cmd = shift;
	my $debug = shift||$global_debug;

	my @res = doGdbCmd("$cmd", $debug);
	if ($res[0] =~ m/^\^done,value=\"(.*)\"/ )
	{
		return $1;
	}
	return undef;

}
#---------------------------------------------------------------
sub getAddrBySymbol
{
	my $name = shift; 
	my $debug = shift||$global_debug;

	my @res = doGdbCmd("-data-evaluate-expression \"$name\"", $debug);	
	if ($res[0] =~ m/^\^done,value=\"(.*)\"/ )
	{
		return $1;
	}
	return undef;
}

#---------------------------------------------------------------
sub disass_func{
	my $addr = shift; 
	my $debug = shift||$global_debug;

	my @res = doGdbCLICmd("x $addr", $debug);
	die "[disass_func]fatal error: failed to disass func at $addr \n@res\n" if not $res[-1] =~ /^\^done/;

	if ($res[0] =~ /<(.*)>/)
	{
		return $1;
	}
	return "?";
}
#---------------------------------------------------------------
sub disass_src{
	my $addr = shift; 
	my $debug = shift||$global_debug;

	my @res = doGdbCLICmd("l *$addr", $debug);
	return "" if not $res[-1] =~ /^\^done/;

	if ($res[0] =~ /\((\S*:\d*)\)/)
	{
		return $1;
	}
	return "";
}
