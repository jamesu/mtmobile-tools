# MT Mobile Framework Tools

Tools to play around, extract & repack files from MT Framework games such as Ace Attorney 5. Currently only supports files generated for iOS.

## decryptArcTool

Unpacks and repacks arc files. Files may be encrypted via blowfish. DLC content is double-encrypted with another key (iapKey).

Usage:

	decryptArcTool create -key 0xFFFFFFFF newArchive.arc <files>
		Creates a new archive based on input files.
	decryptArcTool extract -key 0xFFFFFFFF -cwd output_folder/ archive.arc
		Extracts normal archive.
	decryptArcTool extract -key 0xFFFFFFFF -iapKey mofumofu -cwd output_folder/ iapArchive.arc
		Extracts DLC archive.
	decryptArcTool dump archive.arc
		Decrypts archive.

You will need appropriate encryption key(s) in order to manipulate archives. Such keys are not provided but may be found by looking around.

## gmdTool

Unpacks and repacks gmd message files.

Usage: 

	gmdtool -d infile.gmd outfile.txt
	gmdtool -c infile.txt outfile.gmd

Strings are serialzied to a basic ini-like format

* The first line is the internal id of the gmd. 
* The `@keys` section determines the order of the keys. All keys must be listed.
* Each `[@<key name>]` section contains the text data for that particular key.

## textool

Dumps tex files to tga.

Usage:

	textool -d infile.tex outfile.tex
