#!/usr/bin/perl
package LogAnalyzer;
#DESCRIPTION=Log Analyzer (appearance of lines/matches grouped by time blocks)
#AUTHOR=Maik Block
#YEAR=2016

# ./LogAnalyzer2.pm_new --file "\$(ls -tr /var/log/apache2/access.log*)" --regex "GET " --date-format "DD/mm./yyyy:HH:MM:.." --from_ts $(date -d "$(date -d '2017/12/15 00:00' '+%F %H:%M:00')" '+%s') --to_ts $(date -d "$(date -d '2017/12/18 23:59' '+%F %H:%M:00')" '+%s') --steps 120

use POSIX qw/setlocale LC_TIME strftime ceil/;
POSIX::setlocale(POSIX::LC_TIME, 'en_US');
use Time::Local qw( timelocal_nocheck );

sub new {
	my $class = shift;
	my (%opts) = @_;

	my $outhandle = $opts{OUTHANDLE} || *STDOUT;
	my $moduleANSIColorAvailable = eval {require Term::ANSIColor;1;};

	my $self = {
		OUTHANDLE	=> $outhandle,
		moduleANSIColorAvailable => $moduleANSIColorAvailable
	};
	bless $self, $class;

	return $self;
} 

sub runModule {
	my $self = shift;

	my $OUTHANDLE = $self->{OUTHANDLE};

	my $args = shift;
	my $LOGFILE = $args->{file};

	my $used_time = time();

	my $LOG_CONTENT_DATE;
	if($args->{logdate}) {
		$LOG_CONTENT_DATE = $args->{logdate};
		$used_time = $args->{logdate} if $args->{logdate} =~ /^\d{10}$/;	
	} else {
		$LOG_CONTENT_DATE = strftime("%a %b %e", localtime($used_time));
	}
	my $LOG_DATE_PATTERN;
	if(my $DATE_FORMAT = $args->{date_format}) {
		$LOG_DATE_PATTERN = $DATE_FORMAT;
		
		my @replace_ordered = (
			{ 'pattern' => '[d]+', 'replace' => strftime("%A", localtime($used_time)) },
			{ 'pattern' => '[m]+', 'replace' => strftime("%B", localtime($used_time)) },
			{ 'pattern' => 'yyyy', 'replace' => strftime("%G", localtime($used_time)) },
			{ 'pattern' => 'yy', 'replace' => strftime("%g", localtime($used_time)) },
			{ 'pattern' => 'DD', 'replace' => strftime("%d", localtime($used_time)) },  ## Day with two digit, e.g. 1th will get leading zero => 01
			{ 'pattern' => '_D', 'replace' => strftime("%e", localtime($used_time)) }   ## Day without filling leading zero
		);
		foreach my $replace_hash (@replace_ordered) {
			$LOG_DATE_PATTERN =~ /($replace_hash->{pattern})/g;
			my $len = length "$1";
			my $replace_str = sprintf("%.*s", $len, $replace_hash->{replace});
			$LOG_DATE_PATTERN =~ s/$1/$replace_str/g;
		}

		$LOG_DATE_PATTERN =~ s/HH/%02d/g;
	}

	my $REGEX = $args->{regex};

	my $STEPS = 0;
	$STEPS = $args->{step};

	my $COLUMNS = $args->{size_cols};
	my $LINES = $args->{size_lines};

	#
	# ANALYZING AND OUTPUT
	#
	my %data;
	my $cdata;
	my $max_count = 0;

	my @lines = `zgrep -P \"$REGEX\" $LOGFILE`;

	my $_data = { blocks => undef, total_blocks => undef, screen => undef, max_legend_x_length => undef};


	if($args->{from_ts} and $args->{to_ts} and $args->{from_ts} < $args->{to_ts}) {
		my $from_ts = $args->{from_ts};
		my $to_ts = $args->{to_ts};

		for( my $step=$from_ts; $step<=$to_ts; $step += ($STEPS*60 || 3600) ) {
			if(my $DATE_FORMAT = $args->{date_format}) {
				my $full_date_pattern = $self->calcTimeBlockRegex($step, $step + (($STEPS*60 || 3600)-1), ($STEPS*60 || 3600), $args->{date_format});

				$_data->{blocks}->{$step} = {
					'time' => {
						'H' => strftime("%H", localtime($step)),
						'M' => strftime("%M", localtime($step))
					},
					'date_regex'	=> $full_date_pattern,
					'range'	=> '',
					'count' => 0,
				};
			}
		}
	}


	#
	# Getting count per range from file
	#
	my $total_count = 0;
	foreach my $block_start_ts (sort keys %{$_data->{blocks}}) {
		my $date_regex = $_data->{blocks}->{$block_start_ts}->{date_regex};
		my $block_hour = $_data->{blocks}->{$block_start_ts}->{time}->{H};
		my $block_minute = $_data->{blocks}->{$block_start_ts}->{time}->{M};

		my $count = grep { /$date_regex/ } @lines;

		$total_count += $count;
		$max_count = $count if $count > $max_count;

		my $range;
		if($STEPS) {
			$range = sprintf("%02d:%02d", $block_hour, $block_minute);
			$length = (length "$range") + (length "$count");
		} else {
			$range = $block_hour;
		}
		my $length = (length "$range") + (length "$count");

		$_data->{blocks}->{$block_start_ts}->{range} = $range;
		$_data->{blocks}->{$block_start_ts}->{count} = $count;
		$_data->{max_legend_x_length} = $length if $length > $_data->{max_legend_x_length};
	}

	#
	# Transforming count per range to graphical coordinates in console
	#
	my $x_axis_size = 10;
	my $y_axis_size = 5;
	my $screen_size_x = $COLUMNS || `tput cols`; chomp $screen_size_x;
	my $screen_size_y = $LINES || `tput lines`; chomp $screen_size_y;
	my $steps_number = scalar keys %{$_data->{blocks}};

	my $steps_width = sprintf("%d", ($screen_size_x-$x_axis_size) / $steps_number );

	my @legend;
	my $pointer = 0;
	my $lines_y_axis = ($screen_size_y > 3*$y_axis_size) ? ($screen_size_y-2*$y_axis_size) : 20;
	my $legend_x_width = (length "$LOG_CONTENT_DATE ") + $_data->{max_legend_x_length} + (length ": $max_count"); 

	foreach my $block_start_ts (sort keys %{$_data->{blocks}}) {
		my $block = $_data->{blocks}->{$block_start_ts};

		my $count = $block->{count};

		print $OUTHANDLE sprintf("%-".$legend_x_width."s", $block->{range}.": $count") . "\n" if $args->{verbose};

		my $key = "y" . ($lines_y_axis - sprintf("%d", ($count && $count/$max_count*$lines_y_axis || 0) )) . "|x" . $pointer;
		$_data->{screen}->{$key} = -1;

		my $additional_key = "y" . ($lines_y_axis - sprintf("%d", ($count && $count/$max_count*$lines_y_axis || 0) )-1) . "|x" . $pointer;
		$_data->{screen}->{$additional_key} = $count;

		$pointer++;

		my @range = split("[:-]", $block->{range});
		push @legend, \@range;
	}
	print $OUTHANDLE "="x$legend_x_width . "\nTOTAL= $total_count\n\n" if $args->{verbose};
	print $OUTHANDLE "\n";

	$_data->{total_blocks} = $pointer;

	my %placed_points;
	for(my $i=-1; $i<=$lines_y_axis; $i++) {
		# Build y axis legend part for current line
		my $x_axis_string = $i == -1 ? "" : sprintf(">= %d ", ceil($max_count/$lines_y_axis * ($lines_y_axis-$i)));
		print $OUTHANDLE sprintf("%${x_axis_size}s", $x_axis_string);

		for(my $j=0; $j<$steps_number; $j++) {
			my $output = "";

			if($_data->{screen}->{"y$i|x$j"}) {
				if($_data->{screen}->{"y$i|x$j"} == -1) {
					$output .= "*"x($steps_width);
					$placed_points{$j} = $i;
				} else {
					my $count = $_data->{screen}->{"y$i|x$j"};
					if( $steps_width >= length("$count") ) {
						$output .= sprintf("%-".$steps_width."s", $count);
					} else {
						$output .= " "x($steps_width);
					}
				}
			} else {
				my $sign = " ";
				if( ($j > 0 and !defined $placed_points{$j-1} and defined $placed_points{$j} and $placed_points{$j} < $i)
					or (defined $placed_points{$j} and $placed_points{$j} < $i)
				) {
					$sign = "|";
				}

				$output .= $sign;
				if ($steps_width == 2) { $output .= $sign }
				elsif ($steps_width >= 3) { $output .= " "x($steps_width-2) . $sign };
			}

			$output = $self->coloredIfAvailable($output) if $j%2;
			print $OUTHANDLE $output;
		}
		print $OUTHANDLE "\n";
	}

	#
	# Build the bottom x axis legend
	#
	if( $steps_width >= 4 ) {
		for(my $i=0; $i<scalar @{$legend[0]}; $i++) {
			print $OUTHANDLE " "x$x_axis_size;

			for(my $j=0; $j< scalar @legend ; $j++) {
				my $output;

				if($legend[$j][$i]) {
					$output .= sprintf(" %-".($steps_width-2)."s ", $legend[$j][$i]);
				} else {
					$output .= " "x($steps_width);
				}		

				$output = $self->coloredIfAvailable($output) if $j%2;
				print $OUTHANDLE $output;
			}
			print $OUTHANDLE "\n";
		}
		print $OUTHANDLE "\n"x2;
	}

}

sub nextMinute {
	my ($self, $ts) = @_;
	my @time = localtime($ts);
	return $ts = timelocal_nocheck(0,$time[1]+1,$time[2],$time[3],$time[4],$time[5]);
}
sub nextHour {
	my ($self, $ts) = @_;
	my @time = localtime($ts);
	return $ts = timelocal_nocheck(0,0,$time[2]+1,$time[3],$time[4],$time[5]);
}
sub nextDay {
	my ($self, $ts) = @_;
	my @time = localtime($ts);
	return $ts = timelocal_nocheck(0,0,0,$time[3]+1,$time[4],$time[5]);
}
sub nextMonth {
	my ($self, $ts) = @_;
	my @time = localtime($ts);
	if( ++$time[4] % 12 == 0 ) { $time[5]++ }
	return $ts = timelocal_nocheck(0,0,0,1,$time[4],$time[5]);
}
sub nextYear {
	my ($self, $ts) = @_;
	my @time = localtime($ts);
	return $ts = timelocal_nocheck(0,0,0,1,0,$time[5]+1);
}

sub getReplaceFor {
	my ($self, $ts, $element) = @_;

	my $replace = {
		'year' => [
			{ 'pattern' => 'yyyy', 'replace' => strftime("%G", localtime($ts)) },  ## 4-digit year, e.g. 2017
			{ 'pattern' => 'yy', 'replace' => strftime("%g", localtime($ts)) },  ## 2-digit year, e.g. 17
		],
		'month' => [
			{ 'pattern' => '[m]+', 'replace' => strftime("%B", localtime($ts)) },  ## string month, e.g. mmm => "Oct"
		],
		'day' => [
			{ 'pattern' => '[d]+', 'replace' => strftime("%A", localtime($ts)) },  ## string day, e.g. dd => "Mo", ddd => "Mon"
			{ 'pattern' => 'DD', 'replace' => strftime("%d", localtime($ts)) },  ## 2-digit day, e.g. 1th will get leading zero => 01
			{ 'pattern' => '_D', 'replace' => strftime("%e", localtime($ts)) },   ## day, without filling leading zero
		],
		'hour' => [
			{ 'pattern' => 'HH', 'replace' => strftime("%H", localtime($ts)) },  ## 2-digit day, e.g. 1th will get leading zero => 01
		],
		'minute' => [
			{ 'pattern' => 'MM', 'replace' => strftime("%M", localtime($ts)) },  ## 2-digit day, e.g. 1th will get leading zero => 01
		],
	};

	return @{$replace->{$element}};
}

sub calcTimeBlockRegex {
	my ($self, $ts_start, $ts_end, $step, $date_pattern) = @_;
	my $t_blocks;

	my $replace = {
		'year' => [
			{ 'pattern' => 'yyyy', 'replace' => strftime("%G", localtime($ts_start)) },  ## 4-digit year, e.g. 2017
			{ 'pattern' => 'yy', 'replace' => strftime("%g", localtime($ts_start)) },  ## 2-digit year, e.g. 17
		],
		'month' => [
			{ 'pattern' => '[m]+', 'replace' => strftime("%B", localtime($ts_start)) },  ## string month, e.g. mmm => "Oct"
		],
		'day' => [
			{ 'pattern' => '[d]+', 'replace' => strftime("%A", localtime($ts_start)) },  ## string day, e.g. dd => "Mo", ddd => "Mon"
			{ 'pattern' => 'DD', 'replace' => strftime("%d", localtime($ts_start)) },  ## 2-digit day, e.g. 1th will get leading zero => 01
			{ 'pattern' => '_D', 'replace' => strftime("%e", localtime($ts_start)) },   ## day, without filling leading zero
		],
		'hour' => [
			{ 'pattern' => 'HH', 'replace' => strftime("%H", localtime($ts_start)) },  ## 2-digit day, e.g. 1th will get leading zero => 01
		],
		'minute' => [
			{ 'pattern' => 'MM', 'replace' => strftime("%M", localtime($ts_start)) },  ## 2-digit day, e.g. 1th will get leading zero => 01
		],
	};

	my @start = localtime($ts_start);
	my @end = localtime($ts_end);
	    #      0    1    2     3     4    5     6     7     8
	    #my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)
	my ($s_h1,$s_h2,$s_m1,$s_m2) = split("",sprintf("%02d%02d", $start[2], $start[1]));
	my ($e_h1,$e_h2,$e_m1,$e_m2) = split("",sprintf("%02d%02d", $end[2], $end[1]));

	my $regex;
	my $nextYear = $self->nextYear($ts_start);	
	if($ts_end < $nextYear) {
		foreach my $replace_hash (@{$replace->{'year'}}) {
			$self->replaceOnDatePattern(\$date_pattern, $replace_hash->{pattern}, $replace_hash->{replace});
		}
		my $nextMonth = $self->nextMonth($ts_start);
		if($ts_end < $nextMonth) {
			foreach my $replace_hash (@{$replace->{'month'}}) {
				$self->replaceOnDatePattern(\$date_pattern, $replace_hash->{pattern}, $replace_hash->{replace});
			}
			my $nextDay = $self->nextDay($ts_start);
			if($ts_end < $nextDay) {
				foreach my $replace_hash (@{$replace->{'day'}}) {
					$self->replaceOnDatePattern(\$date_pattern, $replace_hash->{pattern}, $replace_hash->{replace});
				}
				my $nextHour = $self->nextHour($ts_start);
				if($ts_end < $nextHour) {
					foreach my $replace_hash (@{$replace->{'hour'}}) {
						$self->replaceOnDatePattern(\$date_pattern, $replace_hash->{pattern}, $replace_hash->{replace});
					}
					my $nextMinute = $self->nextMinute($ts_start);
					if($ts_end < $nextMinute) {
						foreach my $replace_hash (@{$replace->{'minute'}}) {
							$self->replaceOnDatePattern(\$date_pattern, $replace_hash->{pattern}, $replace_hash->{replace});
						}
					} else {
						$date_pattern = $self->calcMinuteRegex(@start[1], @end[1], $date_pattern);
					}
				} else {
					$date_pattern = $self->calcHourRegex(@start[2,1], @end[2,1], $date_pattern);
				}
			} else {
				$date_pattern = $self->calcDayRegex($ts_start, $ts_end, $date_pattern);
			}
		} else {
			my $date_pattern_1 = $date_pattern;
			foreach my $replace_hash ( $self->getReplaceFor($ts_start, 'month') ) {
				$self->replaceOnDatePattern(\$date_pattern_1, $replace_hash->{pattern}, $replace_hash->{replace});
			}
			$date_pattern_1 = $self->calcDayRegex($ts_start, $nextMonth-1, $date_pattern_1);

			my $preMonth = $nextMonth;
			while(1) { my $tmpNextMonth = $self->nextMonth($preMonth);  if($tmpNextMonth > $ts_end) { last; } else { $preMonth = $tmpNextMonth } };
			(print "ERROR=The time range is not yet support [start:'".(scalar localtime($ts_start))."', end:'".(scalar localtime($ts_end))."'] ...\n\n" and exit) if $nextMonth != $preMonth;

			my $date_pattern_3 = $date_pattern;
			foreach my $replace_hash ( $self->getReplaceFor($ts_end, 'month') ) {
				$self->replaceOnDatePattern(\$date_pattern_3, $replace_hash->{pattern}, $replace_hash->{replace});
			}
			$date_pattern_3 = "|" . $self->calcDayRegex($preMonth, $ts_end, $date_pattern_3) . ")";

			$date_pattern = $date_pattern_1 . $date_pattern_2 . $date_pattern_3;
		}
	} else {
		(print "ERROR=The time range is not yet support [start:'".(scalar localtime($ts_start))."', end:'".(scalar localtime($ts_end))."'] ...\n\n" and exit) if $nextYear;
	}

	return $date_pattern;
}

sub calcMinuteRegex {
	my ($self, $minute_start, $minute_end, $date_pattern) = @_;
	my ($s_m1,$s_m2) = split("",sprintf("%02d", $minute_start));
	my ($e_m1,$e_m2) = split("",sprintf("%02d", $minute_end));

	my $minute_regex;
	if($minute_start == 0 and $minute_end == 59) {
		$minute_regex = ".."; 
	} elsif($s_m1 == $e_m1) {
		$minute_regex = "$s_m1\[$s_m2-$e_m2\]"; 
	} elsif($s_m2 == 0 and $e_m2 == 9) {
		$minute_regex = "\[$s_m1-$e_m1\]."; 
	} else {
		my $diff = $e_m1 - $s_m1;
		$minute_regex = "($s_m1\[$s_m2-9\]";
		if($diff >= 2) {
			$minute_regex .= "|\[".($s_m1+1)."-".($e_m1-1).".\]";
		} 
		$minute_regex .= "|$e_m1\[0-$e_m2\])";
	}
	$date_pattern =~ s/MM/$minute_regex/g;

	return $date_pattern;
} 

sub calcHourRegex {
	my ($self, $hour_start, $minute_start, $hour_end, $minute_end, $date_pattern) = @_;

	my ($s_h1,$s_h2,$s_m1,$s_m2) = split("",sprintf("%02d%02d", $hour_start, $minute_start));
	my ($e_h1,$e_h2,$e_m1,$e_m2) = split("",sprintf("%02d%02d", $hour_end, $minute_end));

	if($hour_start == 0 and $hour_minute == 0 and $hour_end == 23 and $hour_minute == 59) {
		$date_pattern =~ s/(HH|MM)/../g;					
		return $date_pattern;
	}

	my $date_pattern_1 = "($date_pattern";
	$date_pattern_1 =~ s/HH/$s_h1$s_h2/g;
	$date_pattern_1 = $self->calcMinuteRegex($minute_start, 59, $date_pattern_1);

	my $date_pattern_2;
	my $diff = $hour_end - $hour_start;
	if($diff >= 2) {
		$date_pattern_2 = "|$date_pattern";
		my ($s_h1,$s_h2) = split("",sprintf("%02d", $hour_start+1));
		my ($e_h1,$e_h2) = split("",sprintf("%02d", $hour_end-1));
		
		my $hour_regex;
		if($s_h1 == $e_h1) {
			$hour_regex = "$s_h1\[$s_h2-$e_h2\]"; 
		} else {
			my $diff_h1 = $e_h1 - $s_h1;
			$hour_regex = "($s_h1\[$s_h2-9\]";
			if($diff_h1 >= 2) {
				$hour_regex .= "|\[".($s_h1+1)."-".($e_h1-1).".\]";
			} 
			$hour_regex .= "|$e_h1\[0-$e_h2\])";
		}
		$date_pattern_2 =~ s/HH/$hour_regex/g;					
		$date_pattern_2 =~ s/MM/../g;					
	}

	my $date_pattern_3 = "|$date_pattern)";
	$date_pattern_3 =~ s/HH/$e_h1$e_h2/g;
	$date_pattern_3 = $self->calcMinuteRegex(0, $minute_end, $date_pattern_3);

	$date_pattern = $date_pattern_1 . $date_pattern_2 . $date_pattern_3;

	return $date_pattern;
}

sub calcDayRegex {
	my ($self, $ts_start, $ts_end, $date_pattern) = @_;

	my @start = localtime($ts_start);
	my @end = localtime($ts_end);
	my ($day_start, $hour_start, $minute_start, $day_end, $hour_end, $minute_end) = (@start[3,2,1], @end[3,2,1]);

	my $date_pattern_1 = $date_pattern;
	foreach my $replace_hash ( $self->getReplaceFor($ts_start, 'day') ) {
		$self->replaceOnDatePattern(\$date_pattern_1, $replace_hash->{pattern}, $replace_hash->{replace});
	}
	$date_pattern_1 = "(" . $self->calcHourRegex($hour_start, $minute_start, 23, 59, $date_pattern_1);

	my $date_pattern_2;
	my $diff = $day_end - $day_start;
	if($diff >= 2) {
		$date_pattern_2 = $date_pattern;
		my ($s_d1,$s_d2) = split("",sprintf("%02d", $day_start+1));
		my ($e_d1,$e_d2) = split("",sprintf("%02d", $day_end-1));
		
		my $day_regex;
		if($s_d1 == $e_d1) {
			$day_regex = "$s_d1\[$s_d2-$e_d2\]"; 
		} else {
			my $diff_d1 = $e_d1 - $s_d1;
			$day_regex = "($s_d1\[$s_d2-9\]";
			if($diff_d1 >= 2) {
				$day_regex .= "|\[".($s_d1+1)."-".($e_d1-1)."\].";
			} 
			$day_regex .= "|$e_d1\[0-$e_d2\])";
		}
		$date_pattern_2 =~ s/_D/$day_regex/g;					
		$date_pattern_2 =~ s/HH/../g;					
		$date_pattern_2 =~ s/MM/../g;					
		$date_pattern_2 = "|$date_pattern_2";
	}

	my $date_pattern_3 = $date_pattern;
	foreach my $replace_hash ( $self->getReplaceFor($ts_end, 'day') ) {
		$self->replaceOnDatePattern(\$date_pattern_3, $replace_hash->{pattern}, $replace_hash->{replace});
	}
	$date_pattern_3 = "|" . $self->calcHourRegex(0, 0, $hour_end, $minute_end, $date_pattern_3) . ")";

	$date_pattern = $date_pattern_1 . $date_pattern_2 . $date_pattern_3;

	return $date_pattern;
}

sub replaceOnDatePattern {
	my ($self, $date_pattern_ref, $pattern, $value) = @_;

	if( ${$date_pattern_ref} =~ /($pattern)/g ) {
		my $replace_str = sprintf("%.*s", length "$1", $value);
		${$date_pattern_ref} =~ s/$1/$replace_str/g;
	}

	return ${$date_pattern_ref};
}

sub coloredIfAvailable {
	my ($self,$string) = @_;
	return $self->{moduleANSIColorAvailable} ? Term::ANSIColor::colored($string, 'blue') : $string;
}

if (! caller) {
	use Getopt::Long;
	my $args;
	GetOptions(
		"file=s"		=> \$args->{file},		# string
		"logdate=s"		=> \$args->{logdate},
		"date-format=s"		=> \$args->{date_format},	# string
		"regex=s"		=> \$args->{regex},		# string
		"verbose"		=> \$args->{verbose},
		"from=i"		=> \$args->{from},
		"to=i"			=> \$args->{to},
		"from_ts=i"		=> \$args->{from_ts},
		"to_ts=i"		=> \$args->{to_ts},
		"step|steps=i"		=> \$args->{step},
		"size-cols=i"		=> \$args->{size_cols},
		"size-lines=i"		=> \$args->{size_lines}
	) or die("Error in command line arguments\n");

        my $plugin = new LogAnalyzer();
	$plugin->runModule($args);
} 

1;
