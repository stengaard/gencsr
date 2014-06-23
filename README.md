gencsr generates certificate signing requests for you
Usage of gencsr:

 gencsr [opts] <subject> <domain> [<domain> ...]

format of subject is '/C=<country code>/...'
the recognized subject fields are:
	 C (country)
	 ST (state)
	 L (locality)
	 O (organization)
	 OU (organizational unit)
	 SN (serial number)
	 CN (common name).

Options:
  -name="-": File name basis for certificate request. '-' means use stdout.
