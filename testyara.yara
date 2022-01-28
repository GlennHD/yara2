rule Win32_Ransomware_Ackback : test_detection malicious
{
	meta:
		author = "GlennHD"
		source = "GlennHD"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "ACKBACK"
		description = "Yara rule that detects ACKBACK ransomware test."

	strings:
		$main_routine = {

            8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 

        }

	condition:
		all of them
}
