PDFGEN := pdflatex
VIEWER := evince

all: pdf view

pdf: pycrypto.pdf

pycrypto.pdf: pycrypto.latex
	$(PDFGEN) pycrypto.latex

view: pycrypto.pdf
	$(VIEWER) pycrypto.pdf

clean:
	rm -rf *.log *.aux *.*\~

distclean:
	rm -f *.log *.aux *.*\~ *.backup
	rm -f *.pdf

.PHONY: all pdf clean


