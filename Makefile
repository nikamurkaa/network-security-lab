PYTHON ?= python3

.PHONY: all demo test summary check clean rebuild

all: demo

demo:
	$(PYTHON) scripts/generate_demo_pcaps.py

summary: demo
	$(PYTHON) src/pcap_summary.py captures/demo/dns-demo.pcap
	$(PYTHON) src/pcap_summary.py captures/demo/ssh-demo.pcap
	$(PYTHON) src/pcap_summary.py captures/demo/tcp-review-demo.pcap

test: demo
	$(PYTHON) -m unittest discover -s tests -v

check: test
	$(PYTHON) -m compileall -q src scripts tests
	$(PYTHON) scripts/audit_publication.py

clean:
	rm -rf build
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

rebuild: clean all
