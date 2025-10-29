# PSVTHash
Use MD5 and SHA1 hashes to get SHA256 hashes (if available) on VirusTotal

# Usage
1. Download psvthash.ps1
2. Dump MD5 and SHA1 hashes into a .txt file
3. `.\psvthash.ps1 -InputFile .\<file_Containing_MD5_and_SHA1_Hashes>.txt -ApiKey <VirusTotalAPIKey>`
4. Obtain hashes from output .csv file
