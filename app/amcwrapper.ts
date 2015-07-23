/*
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
*/

	//same project cannot be compiled at the same time. put lock=

	//get amc settings not in options.xml
/*
	<allocate_ids>1</allocate_ids>
	<annote_position>case</annote_position>
	<assoc_code>etu</assoc_code>
	<auto_capture_mode>1</auto_capture_mode>
	<code_examen>ASIE 2 14P-R</code_examen>
	<cr>cr</cr>
	<data>data</data>
	<doc_catalog>DOC-catalog.pdf</doc_catalog>
	<doc_question>DOC-sujet.pdf</doc_question>
	<doc_setting>DOC-calage.xy</doc_setting>
	<doc_solution>DOC-corrige.pdf</doc_solution>
	<encodage_csv>UTF-8</encodage_csv>
	<encodage_liste>UTF-8</encodage_liste>
	<export_csv_columns>student.copy,student.key,student.name</export_csv_columns>
	<export_csv_separateur>;</export_csv_separateur>
	<export_include_abs>1</export_include_abs>
	<export_ncols>2</export_ncols>
	<export_ods_columns>student.copy,student.key,student.name</export_ods_columns>
	<export_ods_groupsums>1</export_ods_groupsums>
	<export_ods_stats>1</export_ods_stats>
	<export_ods_statsindic>1</export_ods_statsindic>
	<export_pagesize>a4</export_pagesize>
	<export_sort>l</export_sort>
	<filter>latex</filter>
	<filtered_source>DOC-filtered.tex</filtered_source>
	<format_export>ods</format_export>
	<liste_key>id</liste_key>
	<listeetudiants>%PROJET/all.csv</listeetudiants>
	<maj_bareme>1</maj_bareme>
	<nom_examen>Analyse du SI d'entreprise II</nom_examen>
	<nombre_copies>8</nombre_copies>
	<note_arrondi>sup</note_arrondi>
	<note_grain>0.1</note_grain>
	<note_max>6</note_max>
	<note_max_plafond>1</note_max_plafond>
	<note_min>1</note_min>
	<notes>notes.xml</notes>
	<postcorrect_copy>0</postcorrect_copy>
	<postcorrect_student>0</postcorrect_student>
	<regroupement_compose></regroupement_compose>
	<regroupement_copies>ALL</regroupement_copies>
	<regroupement_type>STUDENTS</regroupement_type>
	<seuil>0.5</seuil>
	<texsrc>%PROJET/source.tex</texsrc>
	<verdict>%(ID) [%(AMC)]
  Note: %(Note)
  Points: %S/%M</verdict>
	<verdict_q>&quot;%s/%m&quot;</verdict_q>
	*/