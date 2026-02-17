import os
import json
from scapy.all import rdpcap, wrpcap, Raw
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.inet import IP, UDP

# Класс для узла бинарного дерева
class TreeNode:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.left = None
        self.right = None

# Класс для бинарного дерева поиска
class BinarySearchTree:
    def __init__(self):
        self.root = None

    def insert(self, key, value):
        if self.root is None:
            self.root = TreeNode(key, value)
        else:
            self._insert_recursive(self.root, key, value)

    def _insert_recursive(self, node, key, value):
        if key < node.key:
            if node.left is None:
                node.left = TreeNode(key, value)
            else:
                self._insert_recursive(node.left, key, value)
        elif key > node.key:
            if node.right is None:
                node.right = TreeNode(key, value)
            else:
                self._insert_recursive(node.right, key, value)
        else:
            node.value = value

    def search(self, key):
        return self._search_recursive(self.root, key)

    def _search_recursive(self, node, key):
        if node is None or node.key == key:
            return node
        if key < node.key:
            return self._search_recursive(node.left, key)
        return self._search_recursive(node.right, key)

# Функция для загрузки таблицы классификации из JSON с приведением MAC к нижнему регистру
def load_classification_table(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    bst = BinarySearchTree()
    for entry in data:
        mac_vlan = (entry['mac'].lower(), entry['vlan'])  # Приведение MAC к нижнему регистру
        bst.insert(mac_vlan, entry['port'])
    return bst

# Функция для классификации пакетов
def classify_packets(pcap_file, bst, output_pcap_files, dropped_file):
    packets = rdpcap(pcap_file)
    classified_packets = {port: [] for port in output_pcap_files.keys()}
    dropped_packets = []

    for packet in packets:
        if IP in packet and UDP in packet:
            dst_mac = packet[Ether].dst.lower()
            vlan = packet[Dot1Q].vlan if Dot1Q in packet else 0
            key = (dst_mac, vlan)
            print(f"Processing packet with MAC: {dst_mac}, VLAN: {vlan}")  # Отладочное сообщение
            node = bst.search(key)
            if node:
                port = node.value
                if port in classified_packets:
                    classified_packets[port].append(packet)
                    print(f"Packet classified to port: {port}")  # Отладочное сообщение
                else:
                    print(f"Port {port} not found in output_pcap_files")  # Отладочное сообщение
            else:
                print(f"No matching port found for key: {key}")  # Отладочное сообщение
                dropped_packets.append(packet)
        else:
            print("Packet does not contain IP or UDP layers")  # Отладочное сообщение

    # Создание пустых файлов для каждого порта с добавлением специального пакета, если нет других пакетов
    for port, file_path in output_pcap_files.items():
        if os.path.exists(file_path):
            os.remove(file_path)  # Удаление старого файла, если он существует

        if not classified_packets[port]:
            # Создание специального пакета с сообщением, только если нет других пакетов
            special_packet = (Ether(dst="FF:FF:FF:FF:FF:FF", src="00:00:00:00:00:00") /
                              Raw(load=b"No packets were sent to this port."))
            wrpcap(file_path, [special_packet])

    for port, packets in classified_packets.items():
        if packets:
            wrpcap(output_pcap_files[port], packets, append=True)
            print(f"Saved {len(packets)} packets to {output_pcap_files[port]}")  # Отладочное сообщение
        else:
            print(f"No packets to save for port {port}")  # Отладочное сообщение

    # Запись сброшенных пакетов в файл dropped.pcap
    if dropped_packets:
        wrpcap(dropped_file, dropped_packets)
        print(f"Saved {len(dropped_packets)} dropped packets to {dropped_file}")  # Отладочное сообщение
    else:
        # Создание пустого файла dropped.pcap с сообщением
        special_packet = (Ether(dst="FF:FF:FF:FF:FF:FF", src="00:00:00:00:00:00") /
                          Raw(load=b"No packets were dropped."))
        wrpcap(dropped_file, [special_packet])
        print(f"No packets were dropped.")  # Отладочное сообщение

# Тестирование
if __name__ == "__main__":
    # Загрузка таблицы классификации
    bst = load_classification_table('input/mac_vlan1.json')
    #bst = load_classification_table('input/mac_vlan2.json')
    #bst = load_classification_table('input/mac_vlan3.json')
    #bst = load_classification_table('input/mac_vlan4.json')
    #bst = load_classification_table('input/mac_vlan5.json')

    # Определение выходных файлов для каждого порта
    output_pcap_files = {
        1: 'output/output_port1.pcap',
        2: 'output/output_port2.pcap',
        3: 'output/output_port3.pcap',
        4: 'output/output_port4.pcap',
        5: 'output/output_port5.pcap'
    }

    # Определение файла для сброшенных пакетов
    dropped_file = 'output/dropped.pcap'

    # Классификация пакетов
    classify_packets('input/input_packets.pcap', bst, output_pcap_files, dropped_file)

    print("Классификация завершена. Пакеты сохранены в соответствующие файлы.")
