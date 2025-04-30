all:
	sed -i '1s|^.*|#!/usr/bin/env python3|' main.py
	dos2unix main.py
	cp main.py bchoc
	chmod +x bchoc
clean:

	rm -f bchoc

