# Build and source scripts

`install-arch.sh` checks the pinned package transaction and installed versions. `capture-packages.sh` retains original producer metadata before cache cleanup. `acquire-sources.py` authenticates archives, binds official recipes and acquires complete sources inside the bounded native container; fetched recipes run without root privileges or capabilities. `capture-installed.py` records actual compiled runtime outputs. `glslc-serial` preserves one shader compiler at a time.
