# Documentation building.

.PHONY: clean coverage docs


clean:
	rm -rf doc
	lein clean


doc:
	mkdir $@
	git clone $$(git remote -v | head -1 | awk '{ print $$2; }') $@
	cd $@ && git symbolic-ref HEAD refs/heads/gh-pages
	rm $@/.git/index
	cd $@ && git clean -fdx


coverage:
	lein cloverage


docs: | doc
	rm -rf doc/api doc/marginalia
	lein docs
