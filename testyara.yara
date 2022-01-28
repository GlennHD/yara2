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
		last_modified = "2022-01-21"
		malware_family = "Malwares"

	strings:
		$a = { 64 A3 00 00 00 00 }
		$b = { 64 89 25 00 00 00 00 }

	condition:
		all of them
}
