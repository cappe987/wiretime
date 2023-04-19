# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
#!/bin/bash

input=$1
output=$2

if [ -z "$input" ]; then
	echo -e "Usage:\n    plot_latency.sh <input-file> <output-file>"
	exit 1
fi
if [ -z "$output" ]; then
	echo -e "Usage:\n    plot_latency.sh <input-file> <output-file>"
	exit 1
fi

gnuplot <<-EOFMarker
	set format y '%0.f'
	set yrange [0:*]
	set xlabel 'Time since start (s)'
	set ylabel 'Latency (ns)'
	set grid mytics
	set grid ytics
	set grid xtics
	set grid mxtics
	set mytics 4
	set mxtics 4
	set xtics nomirror
	set ytics nomirror
	set autoscale xfix
	unset key
	set style line 1 lc rgb '#E41A1C' pt 1 ps 1 lt 1 lw 2 # red
	set terminal pdfcairo enhanced color dashed font 'Arial, 14' rounded size 16 cm, 9.6 cm
	set output '$output'
	plot '$input' with histeps ls 1
EOFMarker
	#set term svg
	#set term png
