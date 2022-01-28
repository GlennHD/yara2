rule test1rule : test1rule
{
	meta:
		author = "GlennHD"
		source = "GlennHD"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "test1yara"
		description = "Yara rule that detects test1yara rule"

	strings:
		$main_routine = {
			AA BB CC EE FF 
        }

	condition:
		all of them
}
