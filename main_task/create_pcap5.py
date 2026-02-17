from scapy.all import wrpcap, Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

# Создаем несколько пакетов с разными MAC-адресами, VLAN-тегами, IP-адресами, портами UDP и длиной данных
packets = [
    # Вариант 5(случайные пакеты)
    Ether(dst="02:13:45:67:89:AB", src="CD:EF:12:34:56:78") / Dot1Q(vlan=15) /
    IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=1234, dport=5678) /
    Raw(load=b"A"*73),

    Ether(dst="23:45:67:89:AB:CD", src="EF:12:34:56:78:9A") / Dot1Q(vlan=25) /
    IP(src="192.168.1.3", dst="192.168.1.4") / UDP(sport=5555, dport=6789) /
    Raw(load=b"B"*73),

    Ether(dst="45:67:89:AB:CD:EF", src="12:34:56:78:9A:BC") / Dot1Q(vlan=30) /
    IP(src="192.168.1.5", dst="192.168.1.6") / UDP(sport=3456, dport=7890) /
    Raw(load=b"C"*73),

    Ether(dst="67:89:AB:CD:EF:12", src="34:56:78:9A:BC:DE") / Dot1Q(vlan=5) /
    IP(src="192.168.1.7", dst="192.168.1.8") / UDP(sport=4567, dport=8901) /
    Raw(load=b"D"*73),

    Ether(dst="89:AB:CD:EF:12:34", src="56:78:9A:BC:DE:F0") / Dot1Q(vlan=10) /
    IP(src="192.168.1.9", dst="192.168.1.10") / UDP(sport=5678, dport=9012) /
    Raw(load=b"E"*73),

    Ether(dst="AB:CD:EF:12:34:56", src="78:9A:BC:DE:F0:12") / Dot1Q(vlan=20) /
    IP(src="192.168.1.11", dst="192.168.1.12") / UDP(sport=6789, dport=10112) /
    Raw(load=b"F"*73),

    Ether(dst="CD:EF:12:34:56:78", src="9A:BC:DE:F0:12:34") / Dot1Q(vlan=35) /
    IP(src="192.168.1.13", dst="192.168.1.14") / UDP(sport=7890, dport=11122) /
    Raw(load=b"G"*73),

    Ether(dst="EF:12:34:56:78:9A", src="BC:DE:F0:12:34:56") / Dot1Q(vlan=50) /
    IP(src="192.168.1.15", dst="192.168.1.16") / UDP(sport=8901, dport=12133) /
    Raw(load=b"H"*73),

    Ether(dst="12:34:56:78:9A:BC", src="DE:F0:12:34:56:78") / Dot1Q(vlan=40) /
    IP(src="192.168.1.17", dst="192.168.1.18") / UDP(sport=9012, dport=13144) /
    Raw(load=b"I"*73),

    Ether(dst="34:56:78:9A:BC:DE", src="F0:12:34:56:78:9A") / Dot1Q(vlan=12) /
    IP(src="192.168.1.19", dst="192.168.1.20") / UDP(sport=10112, dport=14155) /
    Raw(load=b"J"*73),

    Ether(dst="56:78:9A:BC:DE:F0", src="12:34:56:78:9A:BC") / Dot1Q(vlan=22) /
    IP(src="192.168.1.21", dst="192.168.1.22") / UDP(sport=11122, dport=15166) /
    Raw(load=b"K"*73),

    Ether(dst="78:9A:BC:DE:F0:12", src="34:56:78:9A:BC:DE") / Dot1Q(vlan=32) /
    IP(src="192.168.1.23", dst="192.168.1.24") / UDP(sport=12133, dport=16177) /
    Raw(load=b"L"*73),

    Ether(dst="9A:BC:DE:F0:12:34", src="56:78:9A:BC:DE:F0") / Dot1Q(vlan=45) /
    IP(src="192.168.1.25", dst="192.168.1.26") / UDP(sport=13144, dport=17188) /
    Raw(load=b"M"*73),

    Ether(dst="CD:EF:12:34:56:78", src="9A:BC:DE:F0:12:34") / Dot1Q(vlan=35) /
    IP(src="192.168.1.27", dst="192.168.1.28") / UDP(sport=14155, dport=18199) /
    Raw(load=b"N"*73),

    Ether(dst="DE:F0:12:34:56:78", src="9A:BC:DE:F0:12:34") / Dot1Q(vlan=18) /
    IP(src="192.168.1.29", dst="192.168.1.30") / UDP(sport=15166, dport=19210) /
    Raw(load=b"O"*73),
]

# Сохраняем пакеты в файл input_packets.pcap
wrpcap("input/input_packets.pcap", packets)

print("Файл input_packets.pcap успешно создан.")
