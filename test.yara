rule test1yararule : test1yararule
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

            8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 

        }

	condition:
		all of them
}
