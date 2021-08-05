mkdir onepage
for %%p in ("*.pdf") do gswin64c -dBATCH -dNOPAUSE -dSAFER -dPDFSETTINGS=/prepress -sDEVICE=pdfwrite -dFirstPage=1 -dLastPage=1 -sOutputFile="%cd%\onepage\%%p" "%%p"
