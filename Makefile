PYTHON ?= python3
export PYTHONPATH := $(CURDIR)/src
CONFIRM := --confirm=yes-i-understand-butwhy-will-run-this

.PHONY: all test security demo verify-golden check-deps review optimize-proof clean help

all: test security demo verify-golden check-deps review

help:
	@echo "butwhy offline targets: test security demo verify-golden check-deps review optimize-proof"

test:
	$(PYTHON) -m unittest discover -s tests -v

security:
	$(PYTHON) -m unittest tests.test_security -v

demo:
	$(PYTHON) -m butwhy demo --work /tmp/butwhy-make-demo $(CONFIRM)

verify-golden:
	$(PYTHON) tools/verify_golden.py

check-deps:
	$(PYTHON) tools/check_deps.py

review:
	$(PYTHON) tools/review_rounds.py

optimize-proof:
	$(PYTHON) tools/optimize_proof.py

clean:
	rm -rf .butwhy_run /tmp/butwhy-make-demo
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
