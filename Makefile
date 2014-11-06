# Documentation building.

.PHONY: clean docs


clean:
	rm -rf doc


doc:
	mkdir $@
	git clone $$(git remote -v | head -1 | awk '{ print $$2; }') $@
	cd $@ && git symbolic-ref HEAD refs/heads/gh-pages
	rm $@/.git/index
	cd $@ && git clean -fdx


docs: doc
	rm -rf doc/api doc/marginalia
	lein docs
