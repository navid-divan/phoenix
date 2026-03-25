.PHONY: install test bench demo clean

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

bench:
	python run_benchmark.py

demo:
	python scripts/demo_election.py

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true