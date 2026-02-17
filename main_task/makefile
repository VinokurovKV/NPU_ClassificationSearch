.PHONY: run_pcap1 run_pcap2 run_pcap3 run_pcap4 run_pcap5 run_test clean install install_pip install_sudo

# Запуск с create_pcap1.py
run_pcap1:
	@echo "Запуск create_pcap1.py..."
	python create_pcap1.py
	@echo "Запуск основной программы..."
	python binary_search_tree.py

# Запуск с create_pcap2.py
run_pcap2:
	@echo "Запуск create_pcap2.py..."
	python create_pcap2.py
	@echo "Запуск основной программы..."
	python binary_search_tree.py

# Запуск с create_pcap3.py
run_pcap3:
	@echo "Запуск create_pcap3.py..."
	python create_pcap3.py
	@echo "Запуск основной программы..."
	python binary_search_tree.py

# Запуск с create_pcap4.py
run_pcap4:
	@echo "Запуск create_pcap4.py..."
	python create_pcap4.py
	@echo "Запуск основной программы..."
	python binary_search_tree.py

# Запуск с create_pcap5.py
run_pcap5:
	@echo "Запуск create_pcap5.py..."
	python create_pcap5.py
	@echo "Запуск основной программы..."
	python binary_search_tree.py

# Установка зависимостей
install_pip:
	pip install scapy
	pip install ipaddress

install_sudo:
	sudo apt install wireshark
    sudo apt install libpcap-dev tshark

install:
    install_pip install_sudo

# Очистка сгенерированных файлов
clean:
	rm -f *.pcap
	rm -rf output/
	rm -rf __pycache__