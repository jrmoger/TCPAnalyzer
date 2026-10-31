# Makefile for packaging the CSc 361 Assignment 2 submission
#
#   make                  check the code, then build the submission archive
#   make run              run the analyzer on the sample trace
#   make list             show the archive contents
#   make clean            delete the archive
#   make STUDENT_ID=abc   set the student ID used in the archive name

PROGRAM    = TCPAnalyzer.py
README     = readme.txt
TRACE      = sample-capture-file.cap
STUDENT_ID ?= V01044645
ARCHIVE    = TCPAnalyzer.tar.gz

# everything that goes into the submission (add any other source files here)
FILES      = $(PROGRAM) $(README)

.PHONY: all check run list clean

all: check $(ARCHIVE)

check:
	python3 -m py_compile $(PROGRAM)
	rm -rf __pycache__

$(ARCHIVE): $(FILES)
	tar -czvf $@ $(FILES)

run:
	python3 $(PROGRAM) $(TRACE)

list: $(ARCHIVE)
	tar -tzvf $(ARCHIVE)

clean:
	rm -f $(ARCHIVE)