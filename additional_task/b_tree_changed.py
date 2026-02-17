import os
import json
from scapy.all import rdpcap, wrpcap, Raw, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from ipaddress import IPv4Address, IPv4Network
import time
import random
import logging

# Отключаем предупреждения Scapy
conf.logLevel = logging.ERROR

# Собственная реализация B-дерева
class BTreeNode:
    def __init__(self, leaf=False):
        self.leaf = leaf
        self.keys = []
        self.values = []
        self.children = []

class BTree:
    def __init__(self, t=3):
        self.root = BTreeNode(leaf=True)
        self.t = t  # минимальная степень дерева
        self.size = 0  # Добавляем счетчик элементов

    def insert(self, key, value):
        root = self.root
        if len(root.keys) == (2 * self.t) - 1:
            new_root = BTreeNode()
            new_root.children.append(self.root)
            self._split_child(new_root, 0)
            self.root = new_root
            self._insert_non_full(new_root, key, value)
        else:
            self._insert_non_full(root, key, value)
        self.size += 1  # Увеличиваем счетчик при вставке

    def _insert_non_full(self, node, key, value):
        i = len(node.keys) - 1
        if node.leaf:
            node.keys.append(None)
            node.values.append(None)
            while i >= 0 and key < node.keys[i]:
                node.keys[i + 1] = node.keys[i]
                node.values[i + 1] = node.values[i]
                i -= 1
            node.keys[i + 1] = key
            node.values[i + 1] = value
        else:
            while i >= 0 and key < node.keys[i]:
                i -= 1
            i += 1
            if len(node.children[i].keys) == (2 * self.t) - 1:
                self._split_child(node, i)
                if key > node.keys[i]:
                    i += 1
            self._insert_non_full(node.children[i], key, value)

    def _split_child(self, parent, index):
        t = self.t
        child = parent.children[index]
        new_node = BTreeNode(leaf=child.leaf)

        parent.keys.insert(index, child.keys[t - 1])
        parent.values.insert(index, child.values[t - 1])
        parent.children.insert(index + 1, new_node)

        new_node.keys = child.keys[t:(2 * t - 1)]
        new_node.values = child.values[t:(2 * t - 1)]
        child.keys = child.keys[0:(t - 1)]
        child.values = child.values[0:(t - 1)]

        if not child.leaf:
            new_node.children = child.children[t:(2 * t)]
            child.children = child.children[0:t]

    def search(self, key):
        return self._search(self.root, key)

    def _search(self, node, key):
        i = 0
        while i < len(node.keys) and key > node.keys[i]:
            i += 1
        if i < len(node.keys) and key == node.keys[i]:
            return node.values[i]
        elif node.leaf:
            return None
        else:
            return self._search(node.children[i], key)

    def find_all_matches(self, key_func):
        """Находит все записи, удовлетворяющие условию key_func"""
        matches = []
        self._find_all_matches(self.root, key_func, matches)
        return matches

    def _find_all_matches(self, node, key_func, matches):
        if node.leaf:
            for k, v in zip(node.keys, node.values):
                if key_func(k):
                    matches.append((k, v))
        else:
            for i, key in enumerate(node.keys):
                self._find_all_matches(node.children[i], key_func, matches)
                if key_func(key):
                    matches.append((key, node.values[i]))
            self._find_all_matches(node.children[-1], key_func, matches)

    def is_empty(self):
        """Проверяет, пусто ли дерево"""
        return self.size == 0

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
            return node.value if node else None
        if key < node.key:
            return self._search_recursive(node.left, key)
        return self._search_recursive(node.right, key)


# Класс для таблиц классификации
class ClassificationTables:
    def __init__(self):
        # Инициализация B-деревьев для каждой из таблиц
        self.mac_vlan_tree = BTree()
        self.fib_tree = BTree()
        self.arp_tree = BTree()

    # Методы для работы с таблицей MAC-VLAN
    def insert_mac_vlan(self, mac, vlan, port):
        """Вставка записи в таблицу MAC-VLAN."""
        self.mac_vlan_tree.insert((mac, vlan), port)

    # Методы для работы с таблицей FIB
    def insert_fib(self, ip_prefix, prefix_len, next_hop, vlan_id):
        key = (ip_prefix, prefix_len)
        self.fib_tree.insert(key, (next_hop, vlan_id))

    def search_fib(self, ip_address):
        ip = IPv4Address(ip_address)

        # Проверяем, загружена ли таблица
        if self.fib_tree.is_empty():
            print("FIB table is empty, using default values")
            return None

        best_match = None
        best_prefix_len = -1

        # Находим все записи, где IP адрес входит в сеть
        def match_func(prefix_tuple):
            prefix, prefix_len = prefix_tuple
            network = IPv4Network(f"{prefix}/{prefix_len}", strict=False)
            return ip in network

        # Получаем все подходящие записи
        matches = self.fib_tree.find_all_matches(match_func)

        # Выбираем запись с наибольшей длиной префикса
        for (prefix, prefix_len), (next_hop, vlan) in matches:
            if prefix_len > best_prefix_len:
                best_match = (next_hop, vlan)
                best_prefix_len = prefix_len
            elif prefix_len == best_prefix_len:
                # Если длины префиксов равны, выбираем по next_hop
                if next_hop == str(ip):
                    best_match = (next_hop, vlan)

        return best_match

    def search_arp(self, ip_address):
        """Поиск по IP-адресу в таблице ARP."""
        if self.arp_tree.is_empty():
            print("ARP table is empty")
            return None
        return self.arp_tree.search(ip_address)

    def search_mac_vlan(self, mac, vlan):
        """Поиск по MAC и VLAN в таблице MAC-VLAN."""
        if self.mac_vlan_tree.is_empty():
            print("MAC-VLAN table is empty")
            return None
        return self.mac_vlan_tree.search((mac, vlan))

    def _iterate_tree(self, tree):
        """Вспомогательная функция для итерации по всем узлам B-дерева."""
        stack = [(tree.root, False)]
        while stack:
            node, visited = stack.pop()
            if node.leaf:
                for key, value in zip(node.keys, node.values):
                    yield key, value
            else:
                if visited:
                    for i in range(len(node.keys)):
                        yield node.keys[i], node.values[i]
                        stack.append((node.children[i + 1], False))
                else:
                    stack.append((node, True))
                    stack.append((node.children[0], False))

    # Методы для работы с таблицей ARP
    def insert_arp(self, ip_address, mac_address):
        """Вставка записи в таблицу ARP."""
        self.arp_tree.insert(ip_address, mac_address.lower())

    # Функции для загрузки таблиц из JSON
    def load_arp_table(self, json_file):
        with open(json_file, 'r') as f:
            data = json.load(f)
        for entry in data:
            self.insert_arp(entry['ip_next_hop'], entry['mac_next_hop'])

    def load_fib_table(self, json_file):
        with open(json_file, 'r') as f:
            data = json.load(f)
        for entry in data:
            self.insert_fib(entry['ip'], entry['len'], entry['ip_next_hop'], entry['vlan'])

    def load_mac_vlan_table(self, json_file):
        with open(json_file, 'r') as f:
            data = json.load(f)
        for entry in data:
            self.insert_mac_vlan(entry['mac'].lower(), entry['vlan'], entry['port'])

    def test_performance(self, test_size=10000):
        print("\n=== Тестирование производительности ===")

        # Генерация тестовых данных
        test_data = [(f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}",
                      f"00:00:00:00:00:{i % 100:02d}") for i in range(test_size)]

        # Тестирование BST
        start = time.perf_counter()
        bst = BinarySearchTree()
        for ip, mac in test_data:
            bst.insert(ip, mac)
        bst_insert_time = time.perf_counter() - start

        start = time.perf_counter()
        for ip, _ in random.sample(test_data, min(1000, test_size)):
            bst.search(ip)
        bst_search_time = time.perf_counter() - start

        # Тестирование B-дерева
        start = time.perf_counter()
        btree = BTree()
        for ip, mac in test_data:
            btree.insert(ip, mac)
        btree_insert_time = time.perf_counter() - start

        start = time.perf_counter()
        for ip, _ in random.sample(test_data, min(1000, test_size)):
            btree.search(ip)
        btree_search_time = time.perf_counter() - start

        print(f"Результаты для {test_size} элементов:")
        print(f"BST: Вставка = {bst_insert_time:.6f} сек | Поиск = {bst_search_time:.6f} сек")
        print(f"B-дерево: Вставка = {btree_insert_time:.6f} сек | Поиск = {btree_search_time:.6f} сек")
        print("=" * 50 + "\n")


def classify_packets(pcap_file, classification_tables, output_pcap_files, dropped_file):
    packets = rdpcap(pcap_file)
    classified_packets = {port: [] for port in output_pcap_files.keys()}
    dropped_packets = []

    for packet in packets:
        if IP in packet and UDP in packet:
            dst_ip = packet[IP].dst
            print(f"Processing packet with DST IP: {dst_ip}")

            # Инициализация переменных для результатов поиска
            next_hop_ip, next_hop_vlan = None, None
            next_hop_mac = None
            port = None
            should_drop = False

            # 1. Поиск в FIB
            if not classification_tables.fib_tree.is_empty():
                fib_result = classification_tables.search_fib(dst_ip)
                if fib_result:
                    next_hop_ip, next_hop_vlan = fib_result
                    print(f"FIB match: Next Hop: {next_hop_ip}, VLAN: {next_hop_vlan}")
                else:
                    print(f"No FIB match for {dst_ip}")
                    should_drop = True
            else:
                print("FIB table not loaded, using default values")
                next_hop_ip = dst_ip

            if should_drop:
                dropped_packets.append(packet)
                continue

            # 2. Поиск в ARP
            if next_hop_ip:
                if not classification_tables.arp_tree.is_empty():
                    next_hop_mac = classification_tables.search_arp(next_hop_ip)
                    if next_hop_mac:
                        print(f"ARP match found - MAC: {next_hop_mac.upper()}")
                    else:
                        print(f"No ARP entry for {next_hop_ip}")
                        should_drop = True
                else:
                    print("ARP table not loaded, using packet's destination MAC")
                    next_hop_mac = packet[Ether].dst
            else:
                print("No next_hop_ip, cannot search ARP")
                should_drop = True

            if should_drop:
                dropped_packets.append(packet)
                continue

            # 3. Поиск в MAC-VLAN
            if next_hop_mac:
                if not classification_tables.mac_vlan_tree.is_empty():
                    if next_hop_vlan is not None:
                        port = classification_tables.search_mac_vlan(next_hop_mac, next_hop_vlan)
                        if port:
                            print(f"MAC-VLAN match found - Port: {port}, VLAN: {next_hop_vlan}")
                        else:
                            print(f"No MAC-VLAN entry for MAC: {next_hop_mac.upper()}, VLAN: {next_hop_vlan}")
                            should_drop = True
                    else:
                        print("VLAN not specified, searching for any VLAN")
                        for (mac, vlan), p in classification_tables._iterate_tree(classification_tables.mac_vlan_tree):
                            if mac.lower() == next_hop_mac.lower():
                                port = p
                                next_hop_vlan = vlan
                                print(f"Found MAC in VLAN {vlan}, Port: {port}")
                                break
                        if port is None:
                            print(f"No MAC-VLAN entry found for MAC: {next_hop_mac.upper()}")
                            should_drop = True
                else:
                    print("MAC-VLAN table not loaded")
                    should_drop = True
            else:
                print("No next_hop_mac, cannot search MAC-VLAN")
                should_drop = True

            if should_drop:
                dropped_packets.append(packet)
                continue

            # Если дошли до этого места, пакет классифицирован
            if port and port in classified_packets:
                classified_packets[port].append(packet)
            else:
                dropped_packets.append(packet)
        else:
            dropped_packets.append(packet)

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

def main():
    # Создаем выходные каталоги
    os.makedirs('output', exist_ok=True)

    # Инициализация таблиц классификации
    tables = ClassificationTables()

    # Загрузка таблиц
    tables.load_fib_table('input/fib1.json')
    tables.load_arp_table('input/arp1.json')
    tables.load_mac_vlan_table('input/mac_vlan1.json')

    """
    tables.load_fib_table('input/fib2.json')
    tables.load_arp_table('input/arp2.json')
    tables.load_mac_vlan_table('input/mac_vlan2.json')
    """

    # Тестирование производительности
    tables.test_performance()

    # Определение выходных файлов
    output_files = {
        1: 'output/output_port1.pcap',
        2: 'output/output_port2.pcap',
        3: 'output/output_port3.pcap',
        4: 'output/output_port4.pcap',
        5: 'output/output_port5.pcap'
    }
    dropped_file = 'output/dropped.pcap'

    # Классификация пакетов
    classify_packets('input/input_packets.pcap', tables, output_files, dropped_file)


if __name__ == "__main__":
    # Генерация тестовых данных при первом запуске

    main()