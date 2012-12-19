set title "OSpake Performance"

set xlabel "# Client Passwords"
set xtics 1

set ylabel "Time [sec]"

plot "OSpakeTests.txt" using 1:2 title "Server" with linespoints ls 4 lc rgb '#0060ad', "OSpakeTests.txt" using 1:3 title "Client" with linespoints ls 4 lc rgb '#dd181f'
