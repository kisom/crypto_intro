PDFGEN := pdflatex
VIEWER := evince
TARGET := pycrypto

all: pdf view

pdf: $(TARGET).pdf

$(TARGET).pdf: $(TARGET).tex
	$(PDFGEN) $?
	$(PDFGEN) $?

view: $(TARGET).pdf
	$(VIEWER) $(TARGET).pdf

clean:
	rm -rf *.log *.aux *.*\~

distclean:
	rm -f *.log *.aux *.*\~ *.backup
	rm -f *.pdf

.PHONY: all pdf clean


