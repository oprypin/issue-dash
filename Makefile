CRYSTAL ?= crystal
release ?=

md_files = $(wildcard *.md)
html_files := $(md_files:.md=.html)
vendored_files := assets/style.css
all_sources := src/issue_dash.cr $(wildcard src/*.cr) $(wildcard templates/*.html) $(vendored_files)

issue_dash: $(all_sources)
	$(CRYSTAL) build --error-trace $(if $(release),--release )$<

lib: shard.lock
	shards install

shard.lock: shard.yml
	shards update

.PHONY: test
test: $(all_sources)
	crystal spec --order=random

.PHONY: clean
clean:
	rm -f $(html_files) issue_dash

.PHONY: run
run: issue_dash
	./creds.sh ./issue_dash
