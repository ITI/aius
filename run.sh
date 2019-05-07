cd code
if [[($# -eq 1) && ($1 = "real")]]
then
    python edmand.py real &
    python anomaly_analyzer.py &
    bro -Cr ../trace/dnp3_test.pcap end_point.bro &
    wait
else
    python edmand.py simulate &
    python anomaly_analyzer.py &
    wait
fi
