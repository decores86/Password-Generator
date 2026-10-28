<#
    ParooliGeneraator.ps1
    ----------------------
    Graafiline (Windows Forms) parooligeneraator.

    Funktsioonid:
      1. Mitu parooli genereerida
      2. Parooli kogupikkus (tähemärkide arv)
      3. Väikeste tähtede miinimumarv
      4. Suurte tähtede miinimumarv
      5. Numbrite miinimumarv
      6. Sümbolite/kirjavahemärkide miinimumarv
      7. Iga genereeritud parooli järel "COPY" nupp (kopeerib lõikelauale)
      + Parooli turvalisuse (tugevuse) kontroll
      + Parooli lekke kontroll (Have I Been Pwned API, k-anonüümsuse meetod -
        tervet parooli ei saadeta kunagi internetti, ainult SHA1 räsi 5 esimest
        märki)

    Käivitamine:
      Paremklõps failil -> "Run with PowerShell"
      VÕI käsurealt:
        powershell.exe -ExecutionPolicy Bypass -File .\ParooliGeneraator.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
#  ABI-FUNKTSIOONID
# ---------------------------------------------------------------------------

# Krüptograafiliselt turvaline juhuslik indeks vahemikus [0, $max)
$script:RNG = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function Get-SecureRandomIndex {
    param([int]$Max)
    $bytes = New-Object byte[] 4
    $script:RNG.GetBytes($bytes)
    $val = [System.BitConverter]::ToUInt32($bytes, 0)
    return [int]($val % $Max)
}

function Get-RandomChar {
    param([string]$CharSet)
    return $CharSet[(Get-SecureRandomIndex -Max $CharSet.Length)]
}

# Fisher-Yates segamine krüpto-turvalise juhuarvugeneraatoriga
function Invoke-SecureShuffle {
    param([array]$Items)
    $arr = @($Items)
    for ($i = $arr.Length - 1; $i -gt 0; $i--) {
        $j = Get-SecureRandomIndex -Max ($i + 1)
        $tmp = $arr[$i]
        $arr[$i] = $arr[$j]
        $arr[$j] = $tmp
    }
    return $arr
}

# Parooli genereerimise põhifunktsioon
function New-CustomPassword {
    param(
        [int]$Length,
        [int]$MinLower,
        [int]$MinUpper,
        [int]$MinDigits,
        [int]$MinSymbols
    )

    $lower   = 'abcdefghijklmnopqrstuvwxyz'
    $upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $digits  = '0123456789'
    $symbols = '!@#$%^&*()-_=+[]{};:,.<>?/'

    $sumMin = $MinLower + $MinUpper + $MinDigits + $MinSymbols
    if ($sumMin -gt $Length) {
        throw "Miinimumide summa ($sumMin) on suurem kui parooli pikkus ($Length)."
    }

    $chars = New-Object System.Collections.Generic.List[char]

    for ($i = 0; $i -lt $MinLower;   $i++) { $chars.Add((Get-RandomChar $lower))   }
    for ($i = 0; $i -lt $MinUpper;   $i++) { $chars.Add((Get-RandomChar $upper))   }
    for ($i = 0; $i -lt $MinDigits;  $i++) { $chars.Add((Get-RandomChar $digits))  }
    for ($i = 0; $i -lt $MinSymbols; $i++) { $chars.Add((Get-RandomChar $symbols)) }

    # Ülejäänud kohad täidetakse nende kategooriate seast, mis olid valitud
    # (miinimum > 0). Kui midagi polnud valitud, kasutatakse kõiki kategooriaid.
    $pool = ''
    if ($MinLower   -gt 0) { $pool += $lower }
    if ($MinUpper   -gt 0) { $pool += $upper }
    if ($MinDigits  -gt 0) { $pool += $digits }
    if ($MinSymbols -gt 0) { $pool += $symbols }
    if ([string]::IsNullOrEmpty($pool)) { $pool = $lower + $upper + $digits + $symbols }

    $remaining = $Length - $sumMin
    for ($i = 0; $i -lt $remaining; $i++) { $chars.Add((Get-RandomChar $pool)) }

    $shuffled = Invoke-SecureShuffle -Items $chars.ToArray()
    return -join $shuffled
}

# Lihtne entroopiapõhine tugevuse hindamine
function Get-PasswordStrength {
    param([string]$Password)

    $poolSize = 0
    if ($Password -match '[a-z]') { $poolSize += 26 }
    if ($Password -match '[A-Z]') { $poolSize += 26 }
    if ($Password -match '[0-9]') { $poolSize += 10 }
    if ($Password -match '[^a-zA-Z0-9]') { $poolSize += 26 }

    if ($poolSize -eq 0 -or $Password.Length -eq 0) {
        return @{ Bits = 0; Text = "Tundmatu" }
    }

    $entropyBits = [math]::Round($Password.Length * [math]::Log($poolSize, 2), 1)

    $rating =
        if ($entropyBits -lt 28)  { "Väga nõrk" }
        elseif ($entropyBits -lt 36)  { "Nõrk" }
        elseif ($entropyBits -lt 60)  { "Rahuldav" }
        elseif ($entropyBits -lt 100) { "Tugev" }
        else { "Väga tugev" }

    return @{ Bits = $entropyBits; Text = $rating }
}

# Have I Been Pwned lekke kontroll (k-anonüümsus - täisparooli ei saadeta)
function Test-PasswordPwned {
    param([string]$Password)

    try {
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hashHex = -join ($hashBytes | ForEach-Object { $_.ToString("X2") })

        $prefix = $hashHex.Substring(0, 5)
        $suffix = $hashHex.Substring(5)

        $uri = "https://api.pwnedpasswords.com/range/$prefix"
        $response = Invoke-RestMethod -Uri $uri -Method Get -UseBasicParsing -TimeoutSec 10

        $lines = $response -split "`r`n"
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $parts = $line -split ':'
            if ($parts[0] -ieq $suffix) {
                return @{ Leaked = $true; Count = [int]$parts[1] }
            }
        }
        return @{ Leaked = $false; Count = 0 }
    }
    catch {
        return @{ Leaked = $null; Count = 0; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
#  KASUTAJALIIDES (Windows Forms)
# ---------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "Parooli generaator"
$form.Size = New-Object System.Drawing.Size(920, 720)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Sisendite paneel ---
$inputPanel = New-Object System.Windows.Forms.GroupBox
$inputPanel.Text = "Seaded"
$inputPanel.Location = New-Object System.Drawing.Point(10, 10)
$inputPanel.Size = New-Object System.Drawing.Size(880, 150)
$form.Controls.Add($inputPanel)

function New-LabeledNumeric {
    param($Parent, [string]$LabelText, [int]$X, [int]$Y, [int]$Min, [int]$Max, [int]$Default)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $LabelText
    $lbl.Location = New-Object System.Drawing.Point($X, $Y)
    $lbl.Size = New-Object System.Drawing.Size(180, 20)
    $Parent.Controls.Add($lbl)

    $num = New-Object System.Windows.Forms.NumericUpDown
    $num.Location = New-Object System.Drawing.Point(($X + 185), ($Y - 2))
    $num.Size = New-Object System.Drawing.Size(70, 20)
    $num.Minimum = $Min
    $num.Maximum = $Max
    $num.Value = $Default
    $Parent.Controls.Add($num)

    return $num
}

$numCount   = New-LabeledNumeric -Parent $inputPanel -LabelText "Mitu parooli genereerida:"        -X 15  -Y 25 -Min 1 -Max 100 -Default 5
$numLength  = New-LabeledNumeric -Parent $inputPanel -LabelText "Tähemärkide arv (kokku):"          -X 15  -Y 55 -Min 4 -Max 128 -Default 16
$numLower   = New-LabeledNumeric -Parent $inputPanel -LabelText "Väikeseid tähti (min):"             -X 15  -Y 85 -Min 0 -Max 128 -Default 4
$numUpper   = New-LabeledNumeric -Parent $inputPanel -LabelText "Suuri tähti (min):"                 -X 15  -Y 115 -Min 0 -Max 128 -Default 4
$numDigits  = New-LabeledNumeric -Parent $inputPanel -LabelText "Numbreid (min):"                    -X 460 -Y 25 -Min 0 -Max 128 -Default 4
$numSymbols = New-LabeledNumeric -Parent $inputPanel -LabelText "Sümboleid / kirjavahemärke (min):"  -X 460 -Y 55 -Min 0 -Max 128 -Default 4

$btnGenerate = New-Object System.Windows.Forms.Button
$btnGenerate.Text = "Genereeri paroolid"
$btnGenerate.Location = New-Object System.Drawing.Point(460, 95)
$btnGenerate.Size = New-Object System.Drawing.Size(160, 35)
$btnGenerate.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnGenerate.ForeColor = [System.Drawing.Color]::White
$inputPanel.Controls.Add($btnGenerate)

$lblError = New-Object System.Windows.Forms.Label
$lblError.Location = New-Object System.Drawing.Point(15, 130)
$lblError.Size = New-Object System.Drawing.Size(850, 20)
$lblError.ForeColor = [System.Drawing.Color]::Red
$inputPanel.Controls.Add($lblError)

# --- Tulemuste paneel (kerimisega) ---
$resultsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$resultsPanel.Location = New-Object System.Drawing.Point(10, 170)
$resultsPanel.Size = New-Object System.Drawing.Size(880, 500)
$resultsPanel.AutoScroll = $true
$resultsPanel.FlowDirection = "TopDown"
$resultsPanel.WrapContents = $false
$resultsPanel.BorderStyle = "FixedSingle"
$form.Controls.Add($resultsPanel)

# Ühe parooli rea loomine tulemuste paneeli
function Add-PasswordRow {
    param([string]$Password)

    $row = New-Object System.Windows.Forms.FlowLayoutPanel
    $row.FlowDirection = "LeftToRight"
    $row.WrapContents = $false
    $row.AutoSize = $true
    $row.Margin = New-Object System.Windows.Forms.Padding(5)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Text = $Password
    $tb.ReadOnly = $true
    $tb.Font = New-Object System.Drawing.Font("Consolas", 11)
    $tb.Size = New-Object System.Drawing.Size(300, 26)
    $row.Controls.Add($tb)

    $btnCopy = New-Object System.Windows.Forms.Button
    $btnCopy.Text = "COPY"
    $btnCopy.Size = New-Object System.Drawing.Size(70, 26)
    $btnCopy.Tag = $tb
    $btnCopy.Add_Click({
        param($eventSender, $eventArgs)
        $sourceBox = $eventSender.Tag
        [System.Windows.Forms.Clipboard]::SetText($sourceBox.Text)
        $eventSender.Text = "Kopeeritud!"
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 1200
        $timer.Add_Tick({
            param($ts, $ta)
            $btnCopy.Text = "COPY"
            $ts.Stop()
            $ts.Dispose()
        }.GetNewClosure())
        $timer.Start()
    })
    $row.Controls.Add($btnCopy)

    $btnStrength = New-Object System.Windows.Forms.Button
    $btnStrength.Text = "Tugevus"
    $btnStrength.Size = New-Object System.Drawing.Size(80, 26)
    $btnStrength.Tag = $tb
    $row.Controls.Add($btnStrength)

    $btnLeak = New-Object System.Windows.Forms.Button
    $btnLeak.Text = "Lekke kontroll"
    $btnLeak.Size = New-Object System.Drawing.Size(100, 26)
    $btnLeak.Tag = $tb
    $row.Controls.Add($btnLeak)

    $lblResult = New-Object System.Windows.Forms.Label
    $lblResult.Size = New-Object System.Drawing.Size(260, 26)
    $lblResult.TextAlign = "MiddleLeft"
    $row.Controls.Add($lblResult)

    $btnStrength.Add_Click({
        param($eventSender, $eventArgs)
        $box = $eventSender.Tag
        $res = Get-PasswordStrength -Password $box.Text
        $lblResult.Text = "Tugevus: $($res.Text) (~$($res.Bits) bitti)"
        switch ($res.Text) {
            "Väga nõrk" { $lblResult.ForeColor = [System.Drawing.Color]::DarkRed }
            "Nõrk"      { $lblResult.ForeColor = [System.Drawing.Color]::Red }
            "Rahuldav"  { $lblResult.ForeColor = [System.Drawing.Color]::DarkOrange }
            "Tugev"     { $lblResult.ForeColor = [System.Drawing.Color]::Green }
            "Väga tugev"{ $lblResult.ForeColor = [System.Drawing.Color]::DarkGreen }
        }
    }.GetNewClosure())

    $btnLeak.Add_Click({
        param($eventSender, $eventArgs)
        $box = $eventSender.Tag
        $lblResult.Text = "Kontrollin..."
        $lblResult.ForeColor = [System.Drawing.Color]::Black
        [System.Windows.Forms.Application]::DoEvents()

        $res = Test-PasswordPwned -Password $box.Text
        if ($null -eq $res.Leaked) {
            $lblResult.Text = "Kontroll ebaõnnestus (võrguviga)"
            $lblResult.ForeColor = [System.Drawing.Color]::DarkOrange
        }
        elseif ($res.Leaked) {
            $lblResult.Text = "LEKKINUD! Nähtud $($res.Count) korda."
            $lblResult.ForeColor = [System.Drawing.Color]::Red
        }
        else {
            $lblResult.Text = "Ei leitud teadaolevatest leketest."
            $lblResult.ForeColor = [System.Drawing.Color]::Green
        }
    }.GetNewClosure())

    $resultsPanel.Controls.Add($row)
}

# --- Genereeri nupu loogika ---
$btnGenerate.Add_Click({
    $lblError.Text = ""
    $resultsPanel.Controls.Clear()

    $count      = [int]$numCount.Value
    $length     = [int]$numLength.Value
    $minLower   = [int]$numLower.Value
    $minUpper   = [int]$numUpper.Value
    $minDigits  = [int]$numDigits.Value
    $minSymbols = [int]$numSymbols.Value

    try {
        for ($i = 0; $i -lt $count; $i++) {
            $pwd = New-CustomPassword -Length $length -MinLower $minLower -MinUpper $minUpper `
                                       -MinDigits $minDigits -MinSymbols $minSymbols
            Add-PasswordRow -Password $pwd
        }
    }
    catch {
        $lblError.Text = "Viga: $($_.Exception.Message)"
    }
})

[void]$form.ShowDialog()
