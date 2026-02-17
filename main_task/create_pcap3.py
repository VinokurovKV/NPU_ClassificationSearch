from scapy.all import wrpcap, Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import UDP, IP

# Создаем несколько пакетов с разными MAC-адресами и VLAN-тегами
packets = [
    #Вариант 3(каждому порту по 2 пакета):
    Ether(dst="0A:BC:DF:E0:12:34", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=10) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=1234, dport=5678) /
            Raw(load=b"A"*73),
    Ether(dst="0C:DE:F0:12:34:56", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=5555, dport=6789) /
            Raw(load=b"A"*73),
    Ether(dst="0E:F1:23:45:67:89", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=30) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=3456, dport=7890) /
            Raw(load=b"A"*73),
    Ether(dst="10:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=40) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=4567, dport=8901) /
            Raw(load=b"A"*73),
    Ether(dst="12:33:44:55:66:77", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=5678, dport=9012) /
            Raw(load=b"A"*73),
    Ether(dst="0A:BC:DF:E0:12:34", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=10) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=6789, dport=1234) /
            Raw(load=b"A"*73),
    Ether(dst="0C:DE:F0:12:34:56", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=7890, dport=2346) /
            Raw(load=b"A"*73),
    Ether(dst="0E:F1:23:45:67:89", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=30) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=8901, dport=3456) /
            Raw(load=b"A"*73),
    Ether(dst="10:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=40) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=9012, dport=4567) /
            Raw(load=b"A"*73),
    Ether(dst="12:33:44:55:66:77", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=1234, dport=5678) /
            Raw(load=b"A"*73),
]


# Сохраняем пакеты в файл input_packets.pcap
wrpcap("input/input_packets.pcap", packets)

print("Файл input_packets.pcap успешно создан.")
