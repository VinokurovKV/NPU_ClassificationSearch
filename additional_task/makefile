.PHONY: run_pcap1 run_pcap2 run_test clean install install_pip install_sudo

# Запуск с create_pcap1.py
run_pcap1:
	@echo "Запуск create_pcap1.py..."
	python create_pcap1.py
	@echo "Запуск основной программы..."
	python b_tree_changed.py

# Запуск с create_pcap2.py
run_pcap2:
	@echo "Запуск create_pcap2.py..."
	python create_pcap2.py
	@echo "Запуск основной программы..."
	python b_tree_changed.py

# Запуск тестируемой версии
run_test:
	@echo "Запуск тестируемой версии..."
	python b_tree_changed_pytest.py

# Установка зависимостей
install_pip:
	pip install scapy
	pip install pytest
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