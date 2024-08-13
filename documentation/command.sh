#!/bin/bash

pandoc ./code_documentation.md \
-o ./code_documentation.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--highlight-style breezedark \
--resource-path=.:src \
-H disablefloat.tex \
-V colorlinks=true \
-V fontsize=11pt
