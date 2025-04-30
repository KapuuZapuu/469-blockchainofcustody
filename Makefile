all: install bchoc

install:
	python3 -m pip install -r requirements.txt

bchoc: chain_of_custody.py
	cp chain_of_custody.py bchoc
	chmod +x bchoc
	dos2unix bchoc || true