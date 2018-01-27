# print summary of output generated by pwrtest.sh
#
# default results directories are <device>-<date>[-experiment]. By default
# match any device and the year 201*.
#
# Examples:
#
# - show output for all bullhead tests in july 2015:
#    ./pwrsummary.sh -r "bh-201507*"
#
# - generate CSV file for import into spreadsheet:
#    ./pwrsummary.sh -o csv
#

CMDDIR=$(dirname $0 2>/dev/null)
CMDDIR=${CMDDIR:=.}
cd $CMDDIR
CMDDIR=$(pwd)
cd -
POWERAVE="python $CMDDIR/powerave.py"

defaultPattern="*-201*"
defaultVoltage=4.3
defaultFrequency=5

function Usage {
	echo "$0 [-o format] [-v voltage] [-h freq] [-f resultsDirectories]"
}

while [ $# -gt 0 ]
do
	case "$1" in
	(-o) format=$2; shift;;
	(-v) voltage=$2; shift;;
	(-h) hz=$2; shift;;
	(-r) testResults="$2"; shift;;
	(--help) Usage; exit 0;;
	(--) shift; break;;
	(*)
		echo Unknown option: $1
		Usage
		exit 1;;
	esac
	shift
done

testResults=${testResults:=$defaultPattern}
voltage=${voltage:=$defaultVoltage}
hz=${hz:=$defaultFrequency}

function printHeader {
	workload=$1
	units="unknown"
	case $workload in
	(suntemple|shadowgrid2)
		units="FPS";;
	(recentfling|youtube|chrome)
		units="FPS from app point of view: 1/(90th percentile render time)";;
	(sysapps)
		units="App start/switch per second";;
	esac

	echo "Performance unit for $workload is: $units"
	if [ "$format" = csv ]; then
		printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" " " build min ave max net-mA@${voltage}v base-mW net-mW perf/W
	else
		printf "%-30s %-8s %12.12s %12.12s %12.12s %12.12s %12.12s %12.12s %12.12s\n" " " build min ave max net-mA@${voltage}v base-mW net-mW perf/W
	fi
}

function average {
	awk 'BEGIN { count=0; sum=0; max=-1000000000; min=1000000000; }
	{
		cur = $1;
		sum = sum + cur; 
		if (cur > max) max = cur;
		if (cur < min) min = cur;
		count++;
	}

	END {
		if (count > 0) {
			ave = sum / count;
			printf "%.2f %.2f %.2f\n", min, ave, max; 
		}
	}'
}

function hwuiOutputParser {
	# Stats since: 60659316905953ns
	# Total frames rendered: 150
	# Janky frames: 89 (59.33%)
	# 90th percentile: 23ms
	# 95th percentile: 27ms
	# 99th percentile: 32ms
	# Number Missed Vsync: 0
	# Number High input latency: 0
	# Number Slow UI thread: 0
	# Number Slow bitmap uploads: 12
	# Number Slow draw: 89
	# use with "stdbuf -o0 " to disable pipe buffering
	# stdbuf -o0 adb shell /data/hwuitest shadowgrid2 400 | stdbuf -o0 ./hwuitestfilter.sh  | tee t.csv
	sed -e 's/ns//' -e 's/[\(\)%]/ /g' | awk '
	BEGIN { startTime=0; lastTime=0; }
	/^Stats since:/ {
		curTime = $3;
		if (startTime == 0) {
			startTime = curTime;
		}
		if (lastTime) {
			interval = curTime - lastTime;
			fps = totalFrames*1000000000 / interval;
			diffTime = curTime - startTime;
			printf "%.2f, %.2f, ",diffTime/1000000, fps;
		}
	}
	/^Total frames/ { totalFrames=$4; }
	/^Janky frames:/ {
		if (lastTime) {
			printf "%.2f\n",$4; lastTime=curTime;
		}
		lastTime = curTime;
	}'
}

function sysappOutputParser {
	awk '
	BEGIN { fmt=0; count=0; sum=0; }
	/^App/ {
		if (count != 0) {
			if (fmt > 2) printf "Ave: %0.2fms\n", sum/count;
			else printf " %0.2f\n", sum/count;
			count = 0;
			sum = 0;
		}
	}
	/^[a-z]/ { val=$2; if (val != 0) { count++; sum+=val; } }
	/^Iteration/ { if (fmt > 2) printf "%s : ", $0; else if (fmt) printf "%d ", $2; }
	'
}

function calcPerfData {
	testdir=$1
	workload=$2
	baselineCurrent=$3
	baselinePower=$4

	file=${workload}.out
	powerfile=${workload}-power.out
	build="$(cat build 2>/dev/null)"
	build=${build:="Unknown"}

	lines=$(wc -l $file 2>/dev/null | cut -f1 -d\ )

	if [ ${lines:=0} -eq -0 ]; then
		# No performance data captured
		if [ "$format" = csv ]; then
			printf "%s,%s,%s\n" $testdir "$build" "no data"
		else
			printf "%-30s %-8s %12.12s\n" $testdir "$build" "no data"
		fi
		return 1
	fi

	set -- $($POWERAVE $hz $voltage $powerfile)
	current=$(echo $1 $baselineCurrent | awk '{ printf "%.2f", $1-$2; }')
	power=$(echo $2 $baselinePower | awk '{ printf "%.2f", $1-$2; }')

	case $workload in
	(idle)
		set -- 0 0 0
		;;
	(suntemple)
		# units are fps
		set -- $(grep "FPS average" $file  | sed 's/^.*seconds for a //' | awk '{ print $1; }' | average)
		;;
	(recentfling|youtube|chrome)
		# units are ms, so need to convert to app/ms
		set -- $(grep ^Frames:  $file | tr "/" " " | awk '{ print $4; }' | average | awk '{ printf "%.3f %.3f %.3f\n", 1000/$3, 1000/$2, 1000/$1;}'  )
		;;
	(sysapps)
		# units are ms, so need to convert to app/ms
		set -- $(cat $file | sysappOutputParser | average | awk '{ printf "%.3f %.3f %.3f\n", 1000/$3, 1000/$2, 1000/$1;}'  )
		;;
	(shadowgrid2)
		# units are fps
		set -- $(cat $file | hwuiOutputParser | tr ',' ' ' | awk '{print $2;}' | average)
		;;
	esac

	minperf=$1
	aveperf=$2
	maxperf=$3
	perfPerWatt=$(echo $aveperf $power | awk '{ if ($2) { val=$1*1000/$2; printf "%.3f\n", val; } else print "unknown"; }')
	if [ "$format" = csv ]; then
		printf "%s,%s,%f,%f,%f,%f,%f,%f," $testdir "$build" $minperf $aveperf $maxperf $current $baselinePower $power
		printf "%s\n" $perfPerWatt
	else
		printf "%-30s %-8s %12.2f %12.2f %12.2f %12.2f %12.2f %12.2f " $testdir "$build" $minperf $aveperf $maxperf $current $baselinePower $power
		printf "%12s\n" $perfPerWatt
	fi
}

function calcBaselinePower {
	workload=$1
	defaultPowerFile="idle-display-power.out"
	powerFile=$defaultPowerFile
	case $workload in
	(shadowgrid2|suntemple|recentfling)
		powerFile="idle-airplane-display-power.out"
		if [ ! -f  $powerFile ]; then
			powerFile=$defaultPowerFile
		fi;;
	esac
	if [ -f  $powerFile ]; then
		$POWERAVE 5 4.3 $powerFile
	fi
}

for t in $(cat tests)
do
	echo .======================= $t ================================
	printHeader $t
	for i in $testResults
	do
		cd $i
		baseline="$(calcBaselinePower $t)"
		if [ "$baseline" != "" ]; then
	       		calcPerfData $i $t $baseline
		else
			echo "$i : no baseline current"
		fi
		cd - > /dev/null
	done
done
