PYTHON ?= python
.DEFAULT_GOAL := test

.PHONY: install lint format test demo model-sim research-sim visual-sim check clean

install:
	@$(PYTHON) scripts/install.py

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format --check .

test:
	$(PYTHON) -m unittest discover -s tests -p "test*.py" -v

demo:
	$(PYTHON) run_demo.py

model-sim:
	$(PYTHON) run_model_simulation.py

research-sim:
	$(PYTHON) run_research_simulation.py

visual-sim:
	$(PYTHON) run_visual_simulation.py

check:
	$(PYTHON) -m ruff check . && $(PYTHON) -m ruff format --check . && $(PYTHON) scripts/offline_pyright.py && $(PYTHON) -m pytest --cov=vulnassess --cov-fail-under=95

clean:
	@$(PYTHON) -c "import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('data', 'reports')]"
