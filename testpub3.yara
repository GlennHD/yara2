rule testpub3 : testpub3
{
	meta:
		author = "GlennHD"
		source = "GlennHD"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "testpub3"
		description = "Yara rule that detects testpub3 rule"

	strings:
		$main_routine = {AA BB CC EE FF 00 11 22 33 44 55 66 77 88 99 00}
		$main_routine2 = { AA BB CC EE FF 00 11 22 33 44 55 66 77 88 99 00 }
		$main_routine3 = {
			AA BB CC EE FF 00 11 22 33 44 55 66 77 88 99 00
		}
		$ = { AA BB CC EE FF 00 11 22 33 44 55 66 77 88 99 00 }
		$a_string_thing = "here be a string yarrrrrr"
		$another_string = "here be a second stringggg"

	condition:
		all of them
}
