#################################################################################
#
# PowerShell Script to get SHA256 hashes, from MD5 and SHA1 hashes via VirusTotal
#
# Usage
#
# Step 1: Dump MD5 and SHA1 hashes into a .txt file
# Step 2: .\psvthash.ps1 -InputFile .\<fileContainingMD5andSHA1Hashes>.txt -ApiKey <VirusTotalAPIKey>
# Step 3: Obtain hashes from output .csv file
#
#################################################################################

# accept
param (
    [Parameter(Mandatory = $true)]
    [string]$InputFile,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

# Read all MD5 and SHA1 hashes from input file
$hashes = Get-Content -Path $InputFile | Where-Object { $_ -match '^[a-fA-F0-9]{32}$' -or $_ -match '^[a-fA-F0-9]{40}$' }

# VirusTotal API endpoint
$baseUrl = "https://www.virustotal.com/api/v3/files/"

# Store results
$results = @()

foreach ($hash in $hashes) {
    Write-Host "Querying VirusTotal for $hash ..." -ForegroundColor Cyan

    #Retry up to 5 times for rate limit errors
    #Wait 30 seconds between retries
    $success = $false
    $maxRetries = 5
    $attempt = 0

    while (-not $success -and $attempt -lt $maxRetries) 
    {
        try 
        {
            $attempt++

            $url = $baseUrl + $hash

            $response = Invoke-RestMethod -Uri $url -Headers @{
                "x-apikey" = $ApiKey
            } -Method GET -ErrorAction Stop

            $sha256 = $response.data.attributes.sha256

            if ($sha256) 
            {
                Write-Host "  → SHA256: $sha256" -ForegroundColor Green
                $results += [PSCustomObject]@{
                    InitialHash = $hash
                    SHA256 = $sha256
                }
            }
            
            else 
            {
                Write-Host "  → No SHA256 found (possibly unknown hash)" -ForegroundColor Yellow
            }

            $success = $true
        }

        catch 
        {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 429) 
            {
                # Wait for 30 seconds upon getting rate limited by VirusTotal
                Write-Host "  → Rate limit hit, waiting 30 seconds before retry ($attempt/$maxRetries)..." -ForegroundColor Yellow
                Start-Sleep -Seconds 30
            }
            
            else 
            {
                Write-Host "  → Error: $($_.Exception.Message)" -ForegroundColor Red
                $success = $true  # Exit loop on non-retryable errors
            }
        }
    }

    if (-not $success) 
    {
        Write-Host "  → Failed after $maxRetries attempts" -ForegroundColor Red
    }
}

# Export results to CSV
$outputFile = [System.IO.Path]::ChangeExtension($InputFile, ".csv")
$results | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "`nResults saved to $outputFile" -ForegroundColor Cyan
