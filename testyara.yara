import pe32

rule test_yara_modded_gmb : GMB
{
	meta:
		author = "AuthorMan"
		source = "GlennHD"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		categiry - "MALWARE"
		description = "Just a test YARA"
		reports = "CSA-220050"
    modified_by = "GlennHD"
		last_modified = "2022-01-21"
		malware_family = "Malwares"

	strings:
		$ = "abcdefghijklmnop"
		$ = "qrstuvwxyz"


	condition:
		all of them
}
