
$API_KEY = Get-Content (Join-Path -Path $PSScriptRoot -ChildPath "VirusTotal_API_KEY");

# Hashtable to hold filepaths and their corresponding sha256s
$sha256s = [ordered]@{}
$failed = @()

foreach ($file in $Args) {
    $PATH_TO_FILE = $file;

    $Size = Get-ItemProperty $PATH_TO_FILE | Select-Object -ExpandProperty Length

    if ($Size -ge 650*1024*1024)
    {
        Write-Error "Skipping $(file): File bigger than 650 mb is not supported by VirusTotal.";
        continue
    }
    elseif ($Size -ge 32*1024*1024)
    {
        Write-Host "> $PATH_TO_FILE`n  Retrieving large file endpoint...." -NoNewline;
        [string]$endpointResp = curl.exe --request GET `
            --header "x-apikey: ${API_KEY}" `
            'https://www.virustotal.com/api/v3/files/upload_url' -s;

        $j = $endpointResp | ConvertFrom-Json;
        $endpoint = $j.data;

        Write-Host "> $PATH_TO_FILE`n  Uploading to $endpoint...`n" -NoNewline;
        [string]$result = curl.exe --request POST `
        --header 'accept: application/json' `
            --header 'content-type: multipart/form-data' `
            --header "x-apikey: ${API_KEY}" `
            --form "file=@$PATH_TO_FILE" `
            $endpoint -s -w "!$%!#^&@!!%{http_code}";
        
        # Write-Host $result;
    }
    else
    {
        Write-Host "> $PATH_TO_FILE`n  Uploading...." -NoNewline;
        [string]$result = curl.exe --request POST `
        --header 'accept: application/json' `
            --header 'content-type: multipart/form-data' `
            --header "x-apikey: ${API_KEY}" `
            --form "file=@$PATH_TO_FILE" `
            'https://www.virustotal.com/api/v3/files' -s -w "!$%!#^&@!!%{http_code}";
    }
        
    Write-Host "Done!";
    if( -not $? )
        {
        Write-Error "EXIT_CODE: $?"
        Write-Error "Something wrong happened when uploading $PATH_TO_FILE, skipping..."
        $failed += $PATH_TO_FILE
        continue
    }
    $splitted =  $result -Split "!$%!#^&@!!", 2, "simplematch";
    $json = $splitted[0]
    $code = $splitted[1]

    if ("200" -ne $code) {
        Write-Error "Something wrong happened when parsing the response for $PATH_TO_FILE, skipping..."
        Write-Error "Failed to upload: $($code)`n${json}";
        $failed += $PATH_TO_FILE
        continue
    }   

    $j = $json | ConvertFrom-Json;
    $url = $j.data.links.self;

    if ($null -eq $url) {
        Write-Error 'Invalid data, no url given, skipping...'
        $failed += $PATH_TO_FILE
        continue
    }

    if ($Size -ge 32*1024*1024)
    {
        Start-Sleep -Seconds 3
    }

    for ($i = 0; $i -lt 3; $i++) { # retry
        $json = curl.exe `
        --header 'accept: application/json' `
        --header "x-apikey: ${API_KEY}" `
        $url -s;
         
        $j = $json | ConvertFrom-Json;
        $sha256 = $j.meta.file_info.sha256;

        if ($null -eq $sha256) {
            Write-Error 'Invalid data, no sha256 given, retrying...'
            continue
        }

        break
    }

    if ($null -eq $sha256) {
        Write-Error 'Invalid data, no sha256 given, skipping...'
        $failed += $PATH_TO_FILE
        continue
    }

    # Add the file and URL to the hashtable
    $sha256s[$PATH_TO_FILE] = $sha256;

    Set-Clipboard -Value "https://www.virustotal.com/gui/file/$sha256";
    Write-Host "URL copied: https://www.virustotal.com/gui/file/${sha256}";
}

Write-Output "`n### Uploaded:";
# Output the files and their corresponding sha256s
foreach ($file in $sha256s.Keys) {
    Write-Output "- ${file}"
    Write-Output "  https://www.virustotal.com/gui/file/$($sha256s[$file])"
}

if ($failed.Count -gt 0) {
    Write-Output "`n### Failed:";
    # Output the files and their corresponding sha256s
    foreach ($file in $failed) {
        Write-Output "- ${file}";
    }
}


if ($sha256s.Count -eq 0) {
    Read-Host -Prompt "Uploaded 0 file. Press enter to exit...";
    Exit
}

function Open-All {
    foreach ($file in $sha256s.Keys) {
        $url = $sha256s[$file];
        Start-Process "https://www.virustotal.com/gui/file/${url}"
    }
}

function Report {
    $suspicious = 0;
    $malicious = 0;
    $undetected = 0;
    $harmless = 0;
    $other = 0;
    foreach ($file in $sha256s.Keys) {
        $sha256 = $sha256s[$file];
        $json = curl.exe --request GET `
            --header 'accept: application/json' `
            --header "x-apikey: ${API_KEY}" `
            "https://www.virustotal.com/api/v3/files/${sha256}" -s;
        
        $j = $json | ConvertFrom-Json;
        
        Write-Host "`n### ${file}";
        Write-Host "    https://www.virustotal.com/gui/file/$($sha256s[$file])"
        $tmp = if ($null -eq $j.data.attributes.times_submitted) { "?" } else { $j.data.attributes.times_submitted };
        Write-Host "Submitted: " -NoNewline; Write-Host "${tmp}";
        $tmp = if ($null -eq $j.data.attributes.reputation) { "?" } else { $j.data.attributes.reputation };
        Write-Host "Rep: ${tmp} (" -NoNewline;
        $tmp = if ($null -eq $j.data.attributes.total_votes.harmless) { "?" } else { $j.data.attributes.total_votes.harmless };
        Write-Host -ForegroundColor Green "+${tmp}" -NoNewline;
        Write-Host "/" -NoNewLine;
        $tmp = if ($null -eq $j.data.attributes.total_votes.malicious) { "?" } else { $j.data.attributes.total_votes.malicious };
        Write-Host -ForegroundColor Red "-${tmp}" -NoNewline;
        Write-Host ")";
        Write-Host "";

        $stats = $j.data.attributes.last_analysis_stats;
        $sum = $stats.harmless + $stats.suspicious + $stats.undetected + $stats.malicious;

        $tmp = if ($null -eq $stats.'confirmed-timeout') { 0 } else { $stats.'confirmed-timeout' };
        $other += $tmp;
        $tmp = if ($null -eq $stats.timeout) { 0 } else { $stats.timeout };
        $other += $tmp;
        $tmp = if ($null -eq $stats.failure) { 0 } else { $stats.failure };
        $other += $tmp;
        $tmp = if ($null -eq $stats.'type-unsupported') { 0 } else { $stats.'type-unsupported' };
        $other += $tmp;

        $sum += $other;

        if ($null -eq $j.data.attributes.last_analysis_stats -Or $sum -eq 0) {
            Write-Host -ForegroundColor Red "# Analysis data is not yet ready, try query again later.";
        }
        elseif ($null -eq $j.data.attributes.last_analysis_results) {
            Write-Host -ForegroundColor Red "# Analysis data is not yet ready, try query again later.";
        }
        else {
            Write-Host "# Analysis";
            Write-Host "Total: ${sum}";
            $msg = "Malicious: $($stats.malicious) / Suspicious: $($stats.suspicious) / Harmless: $($stats.harmless) / Undetected: $($stats.undetected) / Other: $($other)";
            if ($malicious -gt 0) {
                Write-Host -ForegroundColor Red $msg;
            }
            elseif ($suspicious -gt 0) {
                Write-Host -ForegroundColor Yellow $msg;
            }
            elseif ($undetected -gt 0 -Or $other -gt 0) {
                Write-Host $msg;
            }
            else { 
                Write-Host -ForegroundColor Green $msg;
            }
            foreach ($analysis in $j.data.attributes.last_analysis_results.PsObject.Properties) {
                $analysis = $analysis.Value;
                switch ($analysis.category) {
                    "malicious" {
                        Write-Host -ForegroundColor Red "- $($analysis.engine_name) $($analysis.method) $($analysis.result)";
                    }
                    "suspicious" {
                        Write-Host -ForegroundColor Yellow "- $($analysis.engine_name) $($analysis.method) $($analysis.result)";
                    }
                    "undetected" {}
                    "harmless" {}
                    "type-unsupported" {}
                    default {
                        Write-Host "- [$($analysis.category)] $($analysis.engine_name) $($analysis.method) $($analysis.result)";
                    }
    
                }
            }
            Write-Host "";
        }
        
        if ($null -eq $j.data.attributes.sandbox_verdicts) {
            Write-Host -ForegroundColor Red "# Sandbox Verdicts data not found, it may be not available or not yet ready.";
        }
        else {
            Write-Host "# Sandbox Verdicts";
            $suspicious = 0;
            $malicious = 0;
            $undetected = 0;
            $harmless = 0;
            $other = 0;

            foreach ($v in $j.data.attributes.sandbox_verdicts) {
                switch ($v.category) {
                    "suspicious" { $suspicious++; }
                    "malicous" { $malicous++; }
                    "undetected" { $undetected++; }
                    "harmless" { $harmless++; }
                }
            }

            $stats = "Malicious: ${malicious} / Suspicious: ${suspicious} / Harmless: ${harmless} / Undetected: ${undetected}";
            if ($malicious -gt 0) {
                Write-Host -ForegroundColor Red $stats;
            }
            elseif ($suspicious -gt 0) {
                Write-Host -ForegroundColor Yellow $stats;
            }
            elseif ($undetected -gt 0) {
                Write-Host $stats;
            }
            else { 
                Write-Host -ForegroundColor Green $stats;
            }

            foreach ($v in $j.data.attributes.sandbox_verdicts) {
                switch ($v.category) {
                    "suspicious" { Write-Host -ForegroundColor Red "$($v.category) $($v.malware_classification) $($v.malware_names) ($($v.confidence)) from $($v.sandbox_name)"; }
                    "malicous" { Write-Host -ForegroundColor Red "$($v.category) $($v.malware_classification) $($v.malware_names) ($($v.confidence)) from $($v.sandbox_name)"; }
                    "undetected" { Write-Host -ForegroundColor Red "$($v.category) $($v.malware_classification) $($v.malware_names) ($($v.confidence)) from $($v.sandbox_name)"; }
                    "harmless" { Write-Host -ForegroundColor Red "$($v.category) $($v.malware_classification) $($v.malware_names) ($($v.confidence)) from $($v.sandbox_name)"; }
                }
            }

            Write-Host "";
        }


        if ($null -eq $j.data.attributes.crowdsourced_ids_stats) {
            Write-Host -ForegroundColor Red "# Crowdsourced data not found, it may be not available or not yet ready.";
        }
        else {
            Write-Host "# Crowdsourced";
            $stats = "High: ${j.data.attributes.crowdsourced_ids_stats.high} / Info: ${j.data.attributes.crowdsourced_ids_stats.info} / Medium: ${j.data.attributes.crowdsourced_ids_stats.medium} / Low: ${j.data.attributes.crowdsourced_ids_stats.low}";
            if ($j.data.attributes.crowdsourced_ids_stats.high -gt 0) {
                Write-Host -ForegroundColor Red $stats;
            }
            elseif ($j.data.attributes.crowdsourced_ids_stats.medium -gt 0) {
                Write-Host -ForegroundColor Yellow $stats;
            }
            elseif ($j.data.attributes.crowdsourced_ids_stats.low -gt 0) {
                Write-Host $stats;
            }
            elseif ($j.data.attributes.crowdsourced_ids_stats.info -gt 0) { 
                Write-Host $stats;
            }

            foreach ($r in $j.data.attributes.crowdsourced_ids_results) {
                $msg = "- $($r.rule_category)n$($r.rule_msg)";
                switch ($r.alert_severity) {
                    "high" { Write-Host -ForegroundColor Red $msg; }
                    "medium" { Write-Host -ForegroundColor Yellow $msg; }
                    "low" { Write-Host $msg; }
                    "info" { Write-Host $msg; }
                }
            }
            foreach ($r in $j.data.attributes.crowdsourced_yara_results) {
                $msg = "- $($r.ruleset_name).$($r.rule_name) from $($r.source)`n  - $($r.description)";
                Write-Host -ForegroundColor Red $msg;
            }
            Write-Host "";
        }

        if ($null -eq $j.data.attributes.crowdsourced_ai_results ) {
            Write-Host -ForegroundColor Red "# Crowdsourced AI data not found, it may be not available or not yet ready.";
        }
        else {

            Write-Host "# Crowdsourced AIs";
            foreach ($r in $j.data.attributes.crowdsourced_ai_results) {
                if ($r.verdict) { Write-Host "### $($r.verdict)"; }
                Write-Host "### $($r.category) from $($r.source)";
                Write-Host "------`n$($r.analysis)";
                Write-Host "------";
            }
            Write-Host "# Crowdsource";
        }

        if ($null -eq $j.data.attributes.sigma_analysis_stats) {
            Write-Host -ForegroundColor Red "# Sigma Analysis data not found, it may be not available or not yet ready.";
        }
        else {

            Write-Host "# Sigma Analysis";
            $stats = "High: $($j.data.attributes.sigma_analysis_stats.high) / Critical: $($j.data.attributes.sigma_analysis_stats.critical) / Medium: $($j.data.attributes.sigma_analysis_stats.medium) / Low: $($j.data.attributes.sigma_analysis_stats.low)";
            if ($j.data.attributes.sigma_analysis_stats.high -gt 0 -Or $j.data.attributes.sigma_analysis_stats.critical -gt 0) {
                Write-Host -ForegroundColor Red $stats;
            }
            elseif ($j.data.attributes.sigma_analysis_stats.medium -gt 0) {
                Write-Host -ForegroundColor Yellow $stats;
            }
            elseif ($j.data.attributes.sigma_analysis_stats.low -gt 0) {
                Write-Host $stats;
            }


            foreach ($v in $j.data.attributes.sigma_analysis_results) {
                $msg = "- $($v.rule_title) from $($v.rule_source)`n  - $($v.rule_description)";
                switch ($v.rule_level) {
                    "high" { Write-Host -ForegroundColor Red $msg; }
                    "medium" { Write-Host -ForegroundColor Yellow $msg; }
                    "low" { Write-Host $msg; }
                    "critical" { Write-Host -ForegroundColor Red $msg; }
                }
                foreach ($ctx in $v.match_context) {
                    $msg = $ctx | Format-Table;
                    Write-Host $msg;
                }
            }
            foreach ($v in $j.data.attributes.crowdsourced_yara_results) {
                $msg = "- $($v.ruleset_name).$($v.rule_name) from $($v.source)`n$($v.description)";
                Write-Host -ForegroundColor Red $msg;
            }
            Write-Host "";
        }
        Read-Host -Prompt "Press enter to proceed...";
    }
}

$red = New-Object System.Management.Automation.Host.ChoiceDescription '&Open All', ''
$report = New-Object System.Management.Automation.Host.ChoiceDescription '&Report', ''
$quit = New-Object System.Management.Automation.Host.ChoiceDescription '&Quit', ''

$options = [System.Management.Automation.Host.ChoiceDescription[]]($red, $report, $quit)

$title = '### What now?'
$message = "For brand new unique file, you may want to let VirusTotals scans it for a bit (1 min?) before you continue."
$result = $host.ui.PromptForChoice($title, $message, $options, 1)

switch ($result) {
    0 { Open-All }
    1 { Report }
}

Read-Host -Prompt "Press enter to exit...";
