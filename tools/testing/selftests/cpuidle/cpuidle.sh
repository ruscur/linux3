#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

LOG=cpuidle.log
MODULE=/lib/modules/$(uname -r)/kernel/drivers/cpuidle/test-cpuidle_latency.ko

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4

helpme()
{
	printf "Usage: $0 [-h] [-todg args]
	[-h <help>]
	[-m <location of the module>]
	[-o <location of the output>]
	\n"
	exit 2
}

parse_arguments()
{
	while getopts ht:m:o: arg
	do
		case $arg in
			h) # --help
				helpme
				;;
			m) # --mod-file
				MODULE=$OPTARG
				;;
			o) # output log files
				LOG=$OPTARG
				;;
			\?)
				helpme
				;;
		esac
	done
}

ins_mod()
{
	if [ ! -f "$MODULE" ]; then
		printf "$MODULE module does not exist. Exitting\n"
		exit $ksft_skip
	fi
	printf "Inserting $MODULE module\n\n"
	insmod $MODULE
	if [ $? != 0 ]; then
		printf "Insmod $MODULE failed\n"
		exit $ksft_skip
	fi
}

compute_average()
{
	arr=("$@")
	sum=0
	size=${#arr[@]}
	for i in "${arr[@]}"
	do
		sum=$((sum + i))
	done
	avg=$((sum/size))
}

# Disable all stop states
disable_idle()
{
	for ((cpu=0; cpu<NUM_CPUS; cpu++))
	do
		for ((state=0; state<NUM_STATES; state++))
		do
			echo 1 > /sys/devices/system/cpu/cpu$cpu/cpuidle/state$state/disable
		done
	done
}

# Perform operation on each CPU for the given state
# $1 - Operation: enable (0) / disable (1)
# $2 - State to enable
op_state()
{
	for ((cpu=0; cpu<NUM_CPUS; cpu++))
	do
		echo $1 > /sys/devices/system/cpu/cpu$cpu/cpuidle/state$2/disable
	done
}

# Extract latency in microseconds and convert to nanoseconds
extract_latency()
{
	for ((state=0; state<NUM_STATES; state++))
	do
		latency=$(($(cat /sys/devices/system/cpu/cpu0/cpuidle/state$state/latency) * 1000))
		latency_arr+=($latency)
	done
}

# Run the IPI test
# $1 run for baseline - busy cpu or regular environment
# $2 destination cpu
ipi_test_once()
{
        dest_cpu=$2
        if [ "$1" = "baseline" ]; then
			# Keep the CPU busy
			taskset -c $dest_cpu cat /dev/random > /dev/null &
			task_pid=$!
			# Wait for the workload to achieve 100% CPU usage
			sleep 1
        fi
        taskset 0x1 echo $dest_cpu > /sys/kernel/debug/latency_test/ipi_cpu_dest
        ipi_latency=$(cat /sys/kernel/debug/latency_test/ipi_latency_ns)
        src_cpu=$(cat /sys/kernel/debug/latency_test/ipi_cpu_src)
        if [ "$1" = "baseline" ]; then
			kill $task_pid
			wait $task_pid 2>/dev/null
        fi
}

# Incrementally Enable idle states one by one and compute the latency
run_ipi_tests()
{
        extract_latency
        disable_idle
        declare -a avg_arr
        echo -e "--IPI Latency Test---" >> $LOG

		echo -e "--Baseline IPI Latency measurement: CPU Busy--" >> $LOG
		printf "%s %10s %12s\n" "SRC_CPU" "DEST_CPU" "IPI_Latency(ns)" >> $LOG
		for ((cpu=0; cpu<NUM_CPUS; cpu++))
		do
			ipi_test_once "baseline" $cpu
			printf "%-3s %10s %12s\n" $src_cpu $cpu $ipi_latency >> $LOG
			avg_arr+=($ipi_latency)
		done
		compute_average "${avg_arr[@]}"
		echo -e "Baseline Average IPI latency(ns): $avg" >> $LOG

        for ((state=0; state<NUM_STATES; state++))
        do
			unset avg_arr
			echo -e "---Enabling state: $state---" >> $LOG
			op_state 0 $state
			printf "%s %10s %12s\n" "SRC_CPU" "DEST_CPU" "IPI_Latency(ns)" >> $LOG
			for ((cpu=0; cpu<NUM_CPUS; cpu++))
			do
				# Running IPI test and logging results
				sleep 1
				ipi_test_once "test" $cpu
				printf "%-3s %10s %12s\n" $src_cpu $cpu $ipi_latency >> $LOG
				avg_arr+=($ipi_latency)
			done
			compute_average "${avg_arr[@]}"
			echo -e "Expected IPI latency(ns): ${latency_arr[$state]}" >> $LOG
			echo -e "Observed Average IPI latency(ns): $avg" >> $LOG
			op_state 1 $state
        done
}

# Extract the residency in microseconds and convert to nanoseconds.
# Add 100 ns so that the timer stays for a little longer than the residency
extract_residency()
{
	for ((state=0; state<NUM_STATES; state++))
	do
		residency=$(($(cat /sys/devices/system/cpu/cpu0/cpuidle/state$state/residency) * 1000 + 200))
		residency_arr+=($residency)
	done
}

# Run the Timeout test
# $1 run for baseline - busy cpu or regular environment
# $2 destination cpu
# $3 timeout
timeout_test_once()
{
	dest_cpu=$2
	if [ "$1" = "baseline" ]; then
		# Keep the CPU busy
		taskset -c $dest_cpu cat /dev/random > /dev/null &
		task_pid=$!
		# Wait for the workload to achieve 100% CPU usage
		sleep 1
	fi
	taskset -c $dest_cpu echo $3 > /sys/kernel/debug/latency_test/timeout_expected_ns
	# Wait for the result to populate
	sleep 0.1
	timeout_diff=$(cat /sys/kernel/debug/latency_test/timeout_diff_ns)
	src_cpu=$(cat /sys/kernel/debug/latency_test/timeout_cpu_src)
	if [ "$1" = "baseline" ]; then
		kill $task_pid
		wait $task_pid 2>/dev/null
	fi
}

run_timeout_tests()
{
	extract_residency
	disable_idle
	declare -a avg_arr
	echo -e "\n--Timeout Latency Test--" >> $LOG

	echo -e "--Baseline Timeout Latency measurement: CPU Busy--" >> $LOG
	printf "%s %10s %10s\n" "Wakeup_src" "Baseline_delay(ns)">> $LOG
	for ((cpu=0; cpu<NUM_CPUS; cpu++))
	do
		timeout_test_once "baseline" $cpu ${residency_arr[0]}
		printf "%-3s %13s\n" $src_cpu $timeout_diff >> $LOG
		avg_arr+=($timeout_diff)
	done
	compute_average "${avg_arr[@]}"
	echo -e "Baseline Average timeout diff(ns): $avg" >> $LOG

	for ((state=0; state<NUM_STATES; state++))
	do
		echo -e "---Enabling state: $state---" >> $LOG
		op_state 0 $state
		printf "%s %10s %10s\n" "Wakeup_src" "Baseline_delay(ns)" "Delay(ns)" >> $LOG
		unset avg_arr
		for ((cpu=0; cpu<NUM_CPUS; cpu++))
		do
			timeout_test_once "test" $cpu ${residency_arr[$state]}
			printf "%-3s %13s %18s\n" $src_cpu $baseline_timeout_diff $timeout_diff >> $LOG
			avg_arr+=($timeout_diff)
		done
		compute_average "${avg_arr[@]}"
		echo -e "Expected timeout(ns): ${residency_arr[$state]}" >> $LOG
		echo -e "Observed Average timeout diff(ns): $avg" >> $LOG
		op_state 1 $state
	done
}

declare -a residency_arr
declare -a latency_arr

# Parse arguments
parse_arguments $@

rm -f $LOG
touch $LOG
NUM_CPUS=$(nproc --all)
NUM_STATES=$(ls -1 /sys/devices/system/cpu/cpu0/cpuidle/ | wc -l)

# Insert the module
ins_mod $MODULE

printf "Started IPI latency tests\n"
run_ipi_tests

printf "Started Timer latency tests\n"
run_timeout_tests

printf "Removing $MODULE module\n"
printf "Output logged at: $LOG\n"
rmmod $MODULE
