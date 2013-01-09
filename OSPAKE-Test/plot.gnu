set terminal postscript eps enhanced

set title "OSpake Performance"

set xlabel "# Client Passwords"
set xtics 1

set ylabel "Time [sec]"

#set logscale y

set style line 1 lt 2 lc 1 lw 1 pt 4
set style line 2 lt 3 lc 2 lw 1 pt 4
set style line 3 lt 4 lc 0 lw 1 pt 4
set style line 4 lt 5 lc 3 lw 1 pt 8

set style data lines

#plot "OSpakeTests.txt" using 1:2 title "Server OSpake" ls 1 with linespoints,\
#"OSpakeTests.txt" using 1:4 title "Server Spake" ls 4 with linespoints
plot "OSpakeTests.txt" using 1:3 title "Client OSpake" ls 2 with linespoints,\
"OSpakeTests.txt" using 1:5 title "Client Spake" ls 3 with linespoints
#with linespoints ls 4 lc rgb '#dd181f',\
