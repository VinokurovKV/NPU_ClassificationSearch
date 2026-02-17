from scapy.all import wrpcap, Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

# Создаем несколько пакетов с разными MAC-адресами и VLAN-тегами
packets = [
    #Вариант 2(ни одному порту не сопоставлен пакет):
    Ether(dst="00:1A:2B:3C:4D:5E", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=10) /
        IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=1234, dport=5678) /
            Raw(load=b"A"*73),
    Ether(dst="02:3B:4C:5D:6E:7F", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.3", dst="192.168.2.4") / UDP(sport=5555, dport=6789) /
            Raw(load=b"A"*73),
    Ether(dst="04:5C:6D:7E:8F:9A", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=30) /
        IP(src="192.168.2.5", dst="192.168.2.6") / UDP(sport=3456, dport=7890) /
            Raw(load=b"A"*73),
    Ether(dst="06:7D:8E:9F:AA:BB", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=40) /
        IP(src="192.168.2.7", dst="192.168.2.8") / UDP(sport=4567, dport=8901) /
            Raw(load=b"A"*73),
    Ether(dst="08:9E:AF:BC:CD:DE", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.9", dst="192.168.2.10") / UDP(sport=5678, dport=9012) /
            Raw(load=b"A"*73),
]

# Сохраняем пакеты в файл input_packets.pcap
wrpcap("input/input_packets.pcap", packets)

print("Файл input_packets.pcap успешно создан.")
