.PHONY: install dev test lint security demo evaluate docker clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check src tests

security:
	bandit -q -r src
	pip-audit -r requirements.txt

demo:
	iotsec demo

evaluate:
	iotsec -c config/lab.yaml simulate -o data/eval.pcap --seed 23
	iotsec -c config/lab.yaml evaluate --pcap data/eval.pcap

docker:
	docker compose up --build

clean:
	rm -rf var reports .pytest_cache .ruff_cache data/*.pcap data/*.json models/*.joblib models/*.sig
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
