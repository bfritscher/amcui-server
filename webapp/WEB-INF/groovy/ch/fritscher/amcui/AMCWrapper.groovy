package ch.fritscher.amcui

class AMCWrapper {
	
  def createProject(){
	  
  }
  
  def compileLatex(){
	  
  }
  
  
  def compilePreview  //auto-multiple-choice prepare --mode k --prefix project-dir mcq-source-file
  //def out = new StringBuffer()
  //def proc = "auto-multiple-choice prepare --with pdflatex --filter latex --out-corrige out${File.separator}out.pdf --mode k --n-copies 1 source.tex --latex-stdout".execute(null, new File(PROJECTDIR))
  
  def compileAnswers //?
  
  
  def compilePrint //auto-multiple-choice prepare --mode s --prefix project-dir mcq-source-file
  //compute layout information auto-multiple-choice meptex --src calage.xy --data directory
  
  def print
  //auto-multiple-choice imprime --sujet subject.pdf --fich-nums numbers-file.txt --data data-dir --methode method [where-to-print-arguments...]
    
  def importImages
  //auto-multiple-choice getimages [--copy-to project-scans-dir] [--vector-density density] --list list-file [ scan-files... ]
  
  def analyse
  //auto-multiple-choice analyse --projet project-dir [--seuil-coche threshold] [--tol-marque tol] [ --list-fichiers files-list.txt | scan-files... ]
  
  
  def extractScoringData  //auto-multiple-choice prepare --mode b --data project-data-dir mcq-source-file
  
  def computeMarks
  //auto-multiple-choice note --data project-data-dir [--seuil threshold] [--grain granularity] [--arrondi rounding] [--notemin min] [--notemax max] [ --no-plafond | --plafond ]
  
  def associationAuto
  //auto-multiple-choice association-auto --data project-data-dir --notes-id id --liste students-list.csv [--encodage-liste list-encoding] --liste-key key

  def associateManual
  //auto-multiple-choice association-auto --data project-data-dir --set --student student-sheet-number [--copy copy-number] --id student-id
  
  def annotate
  //auto-multiple-choice annote --projet project-dir --data project-data-dir --fich-assoc assoc.xml [annotation options...]
  //auto-multiple-choice regroupe --projet project-dir --sujet subject.pdf --modele file-name-model --fich-noms students-list.csv [--noms-encodage encoding] [--compose]
  
  def export
  //auto-multiple-choice export --data project-data-dir --module module --fich-noms students-list.csv [--noms-encodage list-encoding] --o output-file
  
}