from scapy.all import wrpcap, Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

# Создаем несколько пакетов с разными MAC-адресами и VLAN-тегами
packets = [
    #Вариант 2(Проверяем по заданной длине префикса):
    Ether(dst="00:11:22:33:44:FF", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=10) /
        IP(src="192.168.2.0", dst="192.168.2.2") / UDP(sport=1234, dport=5678) /
            Raw(load=b"A"*73),  # Указание длины данных
    Ether(dst="66:77:88:99:AA:FF", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.0", dst="192.168.2.4") / UDP(sport=5555, dport=6789) / #2345 - KNET, do not use!
            Raw(load=b"B"*73),
    Ether(dst="CC:DD:EE:FF:00:FF", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=30) /
        IP(src="192.168.2.0", dst="192.168.2.6") / UDP(sport=3456, dport=7890) /
            Raw(load=b"C"*73),
    Ether(dst="EF:D1:65:03:A3:FF", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=40) /
        IP(src="192.168.2.0", dst="192.168.2.8") / UDP(sport=4567, dport=8901) /
            Raw(load=b"D"*73),
    Ether(dst="F5:E3:FF:01:D2:FF", src="aa:bb:cc:dd:ee:ff") / Dot1Q(vlan=20) /
        IP(src="192.168.2.0", dst="192.168.2.10") / UDP(sport=5678, dport=9012) /
            Raw(load=b"E"*73),
]

# Сохраняем пакеты в файл input_packets.pcap
wrpcap("input_packets.pcap", packets)

print("Файл input_packets.pcap успешно создан.")

