rule testpub2 : testpub2
{
	meta:
		author = "GlennHD"
		source = "GlennHD"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "testpub2"
		description = "Yara rule that detects testpub rule"

	strings:
		$main_routine = {AA BB CC EE FF 00 11 22 33 44 55 66 77 88 99 00}
		$a_string_thing = "here be a string yarrrrrr"

	condition:
		all of them
}
