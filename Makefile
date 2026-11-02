.PHONY: help server operator stager clean reset

help:
	@echo "Targets:"
	@echo "  make server    - start the C2 teamserver"
	@echo "  make operator  - start the remote operator (arg HOST=... )"
	@echo "  make stager    - run the stager (arg URL=...)"
	@echo "  make clean     - remove __pycache__"
	@echo "  make reset     - DANGER: delete DB, cert, loot, keys"

server:
	python3 server.py

operator:
	python3 operator.py $(HOST) $(PORT)

stager:
	python3 stager.py $(URL)

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

reset:
	rm -rf c2.db c2.db-* server.crt server.key loot/ __pycache__
	@echo "[!] All generated data deleted."
