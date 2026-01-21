# ANLEITUNG ZUM AUSFÜHREN:
# 1. PowerShell als Administrator starten.
# 2. Ausführen (Interaktiv): .\Convert-VMGeneration_Safe.ps1
#    (Es erscheint eine Liste aller Gen 1 VMs zur Auswahl)
# 3. Ausführen (Direkt):     .\Convert-VMGeneration_Safe.ps1 -VMName "NameDerVM"
# 4. Ausführen (IgnoreRE):   .\Convert-VMGeneration_Safe.ps1 -VMName "NameDerVM" -IgnoreWinRE
#
# ---------------------------------------------------------------------------------------------------------------------------
#
# http://code.msdn.microsoft.com/ConvertVMGeneration
# See the above site for license terms (Microsoft Limited Public License, MS-LPL)
#
# By:                 John Howard                 - Program Manager, Hyper-V Team
# - Prototype & Bulk of code [http://blogs.technet.com/jhoward]
#
# Stefan Wernli, Brian Young - Developers, Hyper-V Team
# - Gave me lots of invaluable assistance. Thank you! :)
#
# Modifications:
# changed to newer Server Versions January 2026 by Matthias Körner https://consoro.eu
# - Added support for newer Windows Server versions (2016/2019/2022/2025)
# - Added interactive menu for VM selection
# - Added safety checks for WinRE
#
# Originally Created:  May - October 2013
#
# About:               Script for converting a Hyper-V virtual machine from generation 1 to generation 2.
# This script is not endorsed or supported by Microsoft Corporation.
#
# Requires:            Windows 8.1/Windows Server 2012 R2 or newer with Hyper-V enabled
#
# History:             23rd Oct 2013, Version 1.01 - First public release
# 31st Oct 2013, Version 1.02 - Additional trace points
# 5th Nov 2013,  Version 1.03 - Additions to tracing
# 6th Dec 2013,  Version 1.04 - Fixed exception in networking cloning
# Jan 2026,      Version 2.0  - Modernized for Server 2025, Interactive Mode, German Localization options
#
# ---------------------------------------------------------------------------------------------------------------------------

<#
.SYNOPSIS
Converts a Hyper-V generation 1 Windows based virtual machine to generation 2
By John Howard, Hyper-V Team, Microsoft Corporation. (c) 2013.
Updated by Matthias Körner (2026).

.DESCRIPTION
This cmdlet automates the conversion process from Gen 1 to Gen 2.
It includes interactive selection and safety checks.

.PARAMETER VMName
The name of the virtual machine to be converted. If omitted, a list is shown.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]

param
(
    # Name der VM (Optional, wenn leer, wird eine Liste angezeigt)
    [string] [alias("Name")] $VMName="",

    # What this script is going to do
    [string] [ValidateSet("Capture", "Apply", "Clone", "All")] $Action="All",

    # Path of new VM (otherwise defaults to same path as source VM)
    [string]$Path="",

    # Check for later version (Defaulted to true/false logic internally)
    [switch] $NoVersionCheck=$True, # Defaulted to True to avoid dead link checks in 2025

    # Check for correct version of PS
    [switch] $NoPSVersionCheck=$False,

    # To be quiet in output
    [switch] $Quiet=$False,

    # Ignore if RE is configured
    [switch] $IgnoreWinRE=$False, 

    # Ignore if PBR is configured
    [switch] $IgnorePBR=$False,

    # Size of the new VHDX
    [int32] [ValidateRange(1,64)] $VHDXSizeGB=0,

    # Name of the VHDX captured
    [string] $VHDX="", 

    # Whether to overwrite the VHDX
    [switch]$OverwriteVHDX=$False,

    # Name of the WIM to use
    [string] $WIM="", 

    # Whether to keep the WIM after it's been used
    [switch] $KeepWIM=$False,

    # Whether to overwrite the WIM if it already exists
    [switch] $OverwriteWIM=$False,

    # Whether to overwrite the VM
    [switch]$OverwriteVM=$False,

    # Name of new VM
    [string] $NewVMName="",

    # To ignore the check for replica
    [switch] $IgnoreReplicaCheck
)

Set-PSDebug -Strict
Set-StrictMode -Version latest

$script:Version = "2.0"                           # Version number updated
$script:LastModified = "Jan 2026"                 # Last modified date
$script:TargetBootDiskMounted = $False            # Is the target VMs boot disk mounted?
$script:TargetDriveLetterESP = ""                 # Drive letter allocated to the ESP on the target disk
$script:TargetDriveLetterWindows = ""             # Drive letter allocated to the Windows partition on the target disk
$script:TargetDriveESPConfigured = $False         # Set to true once diskpart has been run on new VHDX
$script:SourceVMObject = $Null                    # Represents the VM being migrated
$script:SourceBootDiskMounted = $False            # Is the source VMs boot disk mounted?
$script:SourceBootDiskPath = ""                   # From Get-VMDiskDrive for source boot disk
$script:SourceBootDiskWindowsPartition = $Null    # The partition on source VM boot disk
$script:SourceBootDiskWindowsPartitionNum = -1    # The partition number of above
$script:SourceBootDiskWindowsPartitionUsed = 0    # The bytes used on the source windows partition.
$script:CleanupCalled = $False                    # To stop re-entrant calls to cleanup()
$script:WarningCount = 0                          # Number of warnings found
$script:ReachedEndOfProcessing = $False           # Have we got to the end 
$script:TestHookBCDBootWindowsDrive = ""          # Just a test hook.
$script:TestHookIgnoreParameterChecks = $False    # Same deal as above.
[int32]$script:ProgressPoint = 0                  # For tracking exit point

# ---------------------------------------------------------------------------------------------------------------------------
# Function to output progress
# ---------------------------------------------------------------------------------------------------------------------------
Function Write-Info ($info)   { if (!$Quiet){ Write-Host "INFO:    $info" -ForegroundColor Green } }

# ---------------------------------------------------------------------------------------------------------------------------
# Function to cleanup everything when we're going to be quitting
# ---------------------------------------------------------------------------------------------------------------------------
Function Cleanup([string] $sDetail)  {
    if ($script:cleanupcalled) { 
        Write-Verbose "Exiting cleanup as already called"
        exit
    }
    $script:CleanupCalled = $True

    if ($sDetail.Length) { Write-Host -ForegroundColor Red ("`n" + $sDetail + "`n") }

    if (($script:SourceBootDiskMounted -eq $True) -and (($script:SourceBootDiskPath).Length)) {
        Write-Verbose ("Cleanup - unmounting " + ($script:SourceBootDiskPath))
        Dismount-DiskImage ($script:SourceBootDiskPath) -ErrorAction SilentlyContinue
    }

    if ($script:TargetBootDiskMounted -eq $True) {
        Write-Verbose "Cleanup - Unmounting the converted VHDX"
        if ($script:TargetDriveLetterESP -ne "") {
            if ($script:TargetDriveESPConfigured -eq $True) {
                $DiskImage = (Get-DiskImage $VHDX )
                Remove-PartitionAccessPath -disknumber (($DiskImage | Get-Disk).Number) `
                                                 -PartitionNumber 3 `
                                                 -AccessPath $script:TargetDriveLetterESP `
                                                 -ErrorAction SilentlyContinue
            }
        }
        Dismount-DiskImage $VHDX -erroraction SilentlyContinue
    }

    # Delete (or retain) the WIM depending on user selection
    $WIMDeleted = $False
    if ($WIM -ne "") {
        if (!($KeepWIM)) {
            if (Test-Path $WIM) {
                Write-Verbose "Deleting captured image..."
                Remove-Item $WIM -ErrorAction SilentlyContinue
                $WIMDeleted = $True
            }
        }
    }

    if ($sDetail.Length -eq 0) {
        if ($script:ReachedEndOfProcessing) {
            Write-Host ""
            Write-Host -ForegroundColor Cyan "--- ZUSAMMENFASSUNG ---"
            Write-Host -ForegroundColor Cyan "Die Konvertierung wurde erfolgreich abgeschlossen."
            Write-Host -ForegroundColor Cyan "Neue VM: $NewVMName"
            Write-Host -ForegroundColor Cyan "Bitte prüfen Sie die neue VM, bevor Sie die alte löschen."
            Write-Host ""
        } 
    } 
    
    exit
}

# ---------------------------------------------------------------------------------------------------------------------------
# Function to perform parameter validation and INTERACTIVE SELECTION
# ---------------------------------------------------------------------------------------------------------------------------
Function Validate-Parameters {
try {
    Write-Verbose (">>Validate-Parameters")
    $script:ProgressPoint = 100

    # 1. ADMIN CHECK
    $GetCurrent = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$GetCurrent.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) { 
        Cleanup "FEHLER: Dieses Skript muss als Administrator ausgeführt werden!" 
    }

    # 2. INTERACTIVE SELECTION IF VMNAME IS EMPTY
    if ($VMName -eq "") {
        Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "Modus: Interaktive Auswahl" -ForegroundColor Yellow
        Write-Host "Suche nach Generation 1 virtuellen Maschinen..." -ForegroundColor Yellow
        
        # FIX: Force result into array @(...) to ensure .Count property exists even if only 1 VM found
        $Gen1VMs = @(Get-VM | Where-Object { $_.Generation -eq 1 })
        
        if ($Gen1VMs.Count -eq 0) {
            Cleanup "Keine Generation 1 VMs auf diesem Server gefunden."
        }

        Write-Host "Gefundene VMs:"
        $i = 1
        foreach ($vm in $Gen1VMs) {
            Write-Host "[$i] $($vm.Name) (Status: $($vm.State))" -ForegroundColor White
            $i++
        }
        Write-Host ""
        
        $validSelection = $false
        while (-not $validSelection) {
            $selection = Read-Host "Bitte Nummer der VM eingeben, die konvertiert werden soll"
            if ($selection -match "^\d+$" -and [int]$selection -ge 1 -and [int]$selection -le $Gen1VMs.Count) {
                $script:VMName = $Gen1VMs[[int]$selection - 1].Name
                $validSelection = $true
                Write-Host "Ausgewählt: $script:VMName" -ForegroundColor Green
            } else {
                Write-Host "Ungültige Eingabe. Bitte eine Zahl zwischen 1 und $($Gen1VMs.Count) eingeben." -ForegroundColor Red
            }
        }
    } else {
        # Update script scope variable if passed via parameter
        $script:VMName = $VMName
    }

    # 3. SAFETY CHECK (REAGENTC)
    Write-Host ""
    Write-Host "--- SICHERHEITSCHECK ---" -ForegroundColor Yellow
    Write-Host "Damit die Konvertierung erfolgreich ist, muss das Windows Recovery Environment (WinRE)"
    Write-Host "in der Quell-VM deaktiviert sein."
    Write-Host ""
    
    $UserCheck = Read-Host "Hast du in der VM '$script:VMName' den Befehl 'reagentc /disable' ausgeführt? (J/N)"
    
    if ($UserCheck -ne "J" -and $UserCheck -ne "j" -and $UserCheck -ne "Ja" -and $UserCheck -ne "ja") {
        Write-Host ""
        Write-Host "ABBRUCH VOM BENUTZER." -ForegroundColor Red
        Write-Host "BITTE VORGEHENSWEISE BEACHTEN:" -ForegroundColor Green
        Write-Host "1. Starte die VM '$script:VMName'."
        Write-Host "2. Öffne dort CMD als Administrator."
        Write-Host "3. Führe 'reagentc /disable' aus."
        Write-Host "4. Fahre die VM herunter."
        Write-Host "5. Starte dieses Skript erneut."
        Write-Host ""
        exit
    }

    # Rest of validations
    if ($Action -eq "Capture") { $script:KeepWIM = $true }
    if (($WIM.Length) -and (($Action -eq "Apply") -or ($Action -eq "Capture"))) { $script:KeepWIM = $true }

    # Validate VM exists (douple check)
    if ($script:VMName -ne "") {
        $testVM = Get-VM -Name $script:VMName -ErrorAction SilentlyContinue
        if (!$testVM) { Cleanup "VM '$script:VMName' wurde nicht gefunden." }
    }

    Write-Verbose ("<< Validate-Parameters")
}
Catch [Exception] {
    Cleanup ("Exception in Validate-Parameters: " + $_.Exception.ToString())
}
}

# ---------------------------------------------------------------------------------------------------------------------------
# Functions for XML/Version Check (Simplified/Kept for legacy structure but modified logic)
# ---------------------------------------------------------------------------------------------------------------------------
Function Check-LatestVersion($URL) {
    # Always return 0 (Latest) to disable web checks for older MS blogs that don't exist anymore
    return 0 
}

# ---------------------------------------------------------------------------------------------------------------------------
# Function to perform simple preflight migration checks.
# ---------------------------------------------------------------------------------------------------------------------------
Function PreFlight-Checks {
Try {
    Write-Verbose ">> PreFlight_Checks"
    $script:ProgressPoint = 200

    # Check PS Version - FIXED FOR SERVER 2025/Newer PS
    # Original check was -ne 4. We change to -lt 4 to support PS 5 and 7
    if ($global:PSVersionTable.PSVersion.Major -lt 4 -and !$NoPSVersionCheck) {
        Write-Warning "PowerShell Version ist zu alt. Benötigt wird mindestens Version 4.0."
        Cleanup
    }

    if ($script:VMName -ne "") {
        Write-Info "Prüfe virtuelle Maschine '$script:VMName'..."
        $script:SourceVMObject = Get-VM -EA SilentlyContinue -Name $script:VMName
        
        if (!$script:SourceVMObject){ Cleanup "Virtual Machine '$script:VMName' could not be found." }

        # VM must be off
        if ($script:SourceVMObject.State -ne 'Off') { 
	        Cleanup ("'" + $script:VMName + "' muss AUSGESCHALTET sein für die Konvertierung.")
        }

        # Checkpoints
        $Checkpoints = Get-VMSnapshot -VM $script:SourceVMObject -EA SilentlyContinue -SnapshotType Standard
        if ($Checkpoints) { 
            Cleanup "Die VM hat Checkpoints/Snapshots. Bitte löschen Sie diese vor der Konvertierung."
        }

        # Generation 1
        if ($script:SourceVMObject.Generation -ne 1) {
	        Cleanup ("'" + $script:VMName + "' ist keine Generation 1 VM.")
        }
    }
    
    # Target VM Name
    if (($Action -ne "Capture") -and ($Action -ne "Apply")) {
        if ($NewVMName -eq "") {
            $script:NewVMName = ($script:SourceVMObject).VMName + " (Generation 2)"
        }
        $TestTargetVM = Get-VM -EA SilentlyContinue -Name $NewVMName
        if ($TestTargetVM) {
            if ($OverwriteVM) {
                Write-Verbose ("Removing VM " + $NewVMName)
                Remove-VM $TestTargetVM -ErrorAction SilentlyContinue -Force
            } else {
                CleanUp ("Die Ziel-VM '$NewVMName' existiert bereits. Nutzen Sie -OverwriteVM oder löschen Sie sie vorher.")
            }
        }
    }
}
Catch [Exception] {
    Cleanup ("Exception in PreFlight-Checks: " + $_.Exception.ToString())
}
}

# ---------------------------------------------------------------------------------------------------------------------------
# Core Logic Functions (Locate Disk, Partition, Apply, etc.)
# ---------------------------------------------------------------------------------------------------------------------------

Function Locate-SourceBootDisk ( $VM, [Ref] $SourceBootDiskPath) {
try {
    Write-Verbose ">> Locate-SourceBootDisk"
    $SourceBootDiskPath.Value = ""
    $i = 0
    do {
        $Disk = (Get-VMHardDiskDrive $VM -ControllerType IDE -ControllerNumber ([math]::floor([int] $i / [int] 2)) -ControllerLocation ($i%2) -ErrorAction SilentlyContinue) 
        $i++
    } while (($i -le 3) -and (!$Disk))

    if (!($Disk)){ Cleanup "Keine Boot-Disk in der Quell-VM gefunden (IDE Controller)." }
    $SourceBootDiskPath.Value = $Disk.Path
    Write-Info ("Boot-Disk gefunden: '" + $Disk.Path + "'")
}
Catch [Exception] { Cleanup ("Exception in Locate-SourceBootDisk") }
}

Function Mount-Disk ($Path, [Ref] $Mounted) {
try {
    Write-Verbose ">> Mount-Disk"
    $Mounted.Value = $False
    Write-Verbose ("Mounting " + $Path + "...")
    Mount-DiskImage $Path -EA SilentlyContinue
    if (!$?) { Cleanup ("Fehler beim Mounten der VHDX: `n"+ $Error[0][0]) }
    ($Mounted.Value) = $True
}
Catch [Exception] { Cleanup ("Exception in Mount-Disk") }
}

Function Allocate-TwoFreeDriveLetters ([Ref] $First, [Ref] $Second) {
try {
    $First.Value = ""
    $Second.Value = ""
    $TempArray = ls function:[d-z]: -n | ?{ !(test-path $_) } | select -last 2
    if (1 -ne $TempArray.GetUpperBound(0)) { CleanUp "Nicht genügend freie Laufwerksbuchstaben vorhanden." }
    $First.Value = $TempArray[0]
    $Second.Value = $TempArray[1]
}
Catch [Exception] { Cleanup ("Exception in Allocate-TwoFreeDriveLetters") }
}

Function Validate-SourceWindowsInstallation ([String] $BootDiskFileName, [Ref] $ByRefPartition, [Ref] $ByRefPartitionNum, [Ref] $ByRefUsed) {
try {
    $ByRefPartition.Value = $Null
    $ByRefPartitionNum.Value = -1
    $ByRefUsed.Value = 0
    
    $SourcePartitions = ((Get-DiskImage($BootDiskFileName)) | get-disk | get-partition)
    $NumberOfWindowsCopiesFound = 0
    $WorkingPartition = $Null

    if ("GPT" -eq (Get-DiskImage($BootDiskFileName) | Get-Disk ).PartitionStyle) {
        CleanUp ("Die Quell-Disk ist GPT. Eine Gen 1 VM sollte MBR haben.")
    }

    $SourcePartitions | ForEach-Object {
        if ($_.DriveLetter -match "^[a-zA-Z]") {
            if ($True -eq (Test-Path (($_.DriveLetter) + ":\windows\system32\ntdll.dll"))) { 
                $NumberOfWindowsCopiesFound++
                $WorkingPartition = $_ 
                $ByRefPartition.Value = $WorkingPartition
                $ByRefPartitionNum.Value = $_.PartitionNumber
            }
        }
    }

    if ($NumberOfWindowsCopiesFound -eq 0) { CleanUp "Keine Windows-Installation auf der Quell-Disk gefunden. (Laufwerksbuchstaben zugewiesen?)" }
    if ($NumberOfWindowsCopiesFound -gt 1) { CleanUp "Mehrere Windows-Installationen gefunden. Nicht unterstützt." }
      
    $SourceNTDLL = ($WorkingPartition.DriveLetter) + ":\windows\system32\ntdll.dll"
    $SourceProductName = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($SourceNTDLL).ProductName)
    
    Write-Info ("Windows gefunden: $SourceProductName auf " + $WorkingPartition.DriveLetter + ":\")

    $vol = ($WorkingPartition | get-volume)
    $ByRefUsed.Value = (($vol.Size) - ($Vol.SizeRemaining))
}
Catch [Exception] { Cleanup ("Exception in Validate-SourceWindowsInstallation") }
}

Function Verify-RecoveryEnvironment ([String] $SourceBootDiskWindowsPartitionDriveLetter) {
try {
    # Basic check - users confirmed strictly in interactive mode already.
    # We maintain this for automated runs without params.
    if ($True -eq (Test-Path ($SourceBootDiskWindowsPartitionDriveLetter + ":\windows\system32\recovery\reagent.xml"))) {
        [System.Xml.XmlDocument] $XMLDocument = new-object System.Xml.XmlDocument
        $XMLDocument.Load($SourceBootDiskWindowsPartitionDriveLetter + ":\windows\system32\recovery\reagent.xml")
        $XMLNodes = $XMLDocument.SelectNodes("/WindowsRE/InstallState")

        if ($XMLNodes.Count -gt 0) {
            if (1 -eq $XMLNodes.State) {
                if (!$IgnoreWinRE) {
                    # Interaktive Abfrage, um Abbruch zu vermeiden
                    Write-Host ""
                    Write-Warning "PROBLEM ERKANNT: WinRE ist laut Konfigurationsdatei noch AKTIV."
                    Write-Host "Dies passiert oft, wenn die VM nicht sauber heruntergefahren wurde oder der Befehl nicht griff." -ForegroundColor Yellow
                    
                    $ForceContinue = Read-Host "Möchten Sie die Warnung ignorieren und TROTZDEM fortfahren? (J/N)"
                    
                    if ($ForceContinue -eq "J" -or $ForceContinue -eq "ja") {
                        Write-Warning "Fahre fort trotz aktivem WinRE..."
                    } else {
                        CleanUp "WinRE ist aktiv. Bitte 'reagentc /disable' in der VM ausführen oder -IgnoreWinRE nutzen."
                    }
                } else {
                    Write-Warning "WinRE ist aktiv markiert, wird aber ignoriert (-IgnoreWinRE gesetzt)."
                }                
            }
        }
    } 
}
Catch [Exception] { Cleanup ("Exception in Verify-RecoveryEnvironment") }
}

Function Capture-ImageOfSourceVHDX ( $SourceDriveLetter ) {
try {
    if ($WIM -eq "") {
        $WIM = "$env:temp\TEMP-$(Get-Date -format 'yyyy-MM-dd hh-mm-ss') captured.wim"      
        $script:WIM = $WIM
    }
    Write-Info ("Erfasse Abbild der Quell-VM. Das kann dauern...")        
    $DismCommand = 'dism /capture-image /imagefile:"' + $WIM + '" /name:"Captured" /capturedir:"' + $SourceDriveLetter + ':\"'
    $DismCaptureOutput = Invoke-Expression $DismCommand
    if (0 -ne $global:lastexitcode) { Cleanup ("Dism Capture fehlgeschlagen.") }
    Write-Info ("Image erstellt unter: " + $WIM)
}
Catch [Exception] { Cleanup ("Exception in Capture-ImageOfSourceVHDX") }
}

Function Generate-PathToTargetBootDisk( [String] $SourceVHDX) {
try {
    if ($VHDX -eq "") { 
        if ($Path -eq "") {
            $VHDX = [System.IO.Path]::ChangeExtension($SourceVHDX, $null)
            $VHDX  = $VHDX.SubString(0, $VHDX.Length-1) + " (Generation 2).vhdx"
        } else {
            $VHDX = [System.IO.Path]::Combine(([System.IO.Path]::Combine($Path,$NewVMName)),([System.IO.Path]::GetFileName($SourceVHDX)))
            $VHDX = [System.IO.Path]::ChangeExtension($VHDX, $null)
            $VHDX  = $VHDX.SubString(0, $VHDX.Length-1) + " (Generation 2).vhdx"
        }
    }
    $script:VHDX = $VHDX
}
Catch [Exception] { Cleanup ("Exception in Generate-PathToTargetBootDisk") }
}

Function Create-TargetVHDX ($SizeOfSourcePartition) {
try {
    if (Test-Path ($VHDX)) { 
        if (!$OverwriteVHDX){ Cleanup "$VHDX existiert bereits. Nutzen Sie -OverwriteVHDX." }
        Dismount-VHD $VHDX -EA SilentlyContinue
        Remove-Item $VHDX -ErrorAction SilentlyContinue
    }
    
    if ($VHDXSizeGB -eq 0) {
        $TargetVHDSize = (300*1024*1024) + (100*1024*1024) + (128*1024*1024) + $SizeOfSourcePartition
    } else {
        $TargetVHDSize = ($VHDXSizeGB * 1024 * 1024 * 1024)
        $SpaceRequired = $script:SourceBootDiskWindowsPartitionUsed + (528*1024*1024)
        if ($TargetVHDSize -lt $SpaceRequired) { Cleanup "Zielgröße ist zu klein für die Daten." }
    }

    Write-Info ("Erstelle neue VHDX: '" + $VHDX + "'...")
    $TargetVHD = New-VHD -Path $VHDX -Fixed -Size $TargetVHDSize -ErrorAction SilentlyContinue
    if (!$?) { Cleanup ("Fehler beim Erstellen der VHDX.") }
}
Catch [Exception] { Cleanup ("Exception in Create-TargetVHDX") }
}

Function Partition-TargetVHDX($ESPDriveLetter, $WindowsDriveLetter, [Ref] $ESPConfigured) {
Try {
    $DiskImage = Get-DiskImage $VHDX -ErrorAction SilentlyContinue
    $DiskNumber = ($DiskImage | Get-Disk -ErrorAction SilentlyContinue).Number
    
    Write-Info "Ziel-Disk $DiskNumber gemountet. Buchstaben: $ESPDriveLetter und $WindowsDriveLetter"

    $DiskPartFileName = "$env:temp\TEMP-$(Get-Date -format 'yyyy-MM-dd hh-mm-ss') DiskpartTemp.log"  
    New-Item $DiskPartFilename -itemType File -ErrorAction SilentlyContinue | Out-Null

    Add-Content $DiskPartFileName ("select disk " + ($DiskNumber.ToString()))
    Add-Content $DiskPartFileName "clean"
    Add-Content $DiskPartFileName "convert gpt"
    # Recovery
    Add-Content $DiskPartFileName "create partition efi size=300"
    Add-Content $DiskPartFileName "format quick fs=ntfs label=""Windows RE tools"""
    Add-Content $DiskPartFileName "set id=""de94bba4-06d1-4d40-a16a-bfd50179d6ac"""
    Add-Content $DiskPartFileName "gpt attributes=0x8000000000000001"
    # ESP
    Add-Content $DiskPartFileName "create partition efi size=100"
    Add-Content $DiskPartFileName "format quick fs=fat32 label=""System"""
    Add-Content $DiskPartFileName ('assign letter="' + $ESPDriveLetter + '"')
    # MSR
    Add-Content $DiskPartFileName "create partition msr size=128"
    # OS
    Add-Content $DiskPartFileName "create partition primary"
    Add-Content $DiskPartFileName "format quick fs=ntfs label=""Windows"""
    Add-Content $DiskPartFileName ('assign letter="' + $WindowsDriveLetter + '"')
    Add-Content $DiskPartFileName "exit"

    # Sicherheitsabfrage entfällt hier, da oben im interaktiven Teil bereits geklärt oder per Parameter bestätigt.
    # Wir führen es direkt aus.
    Write-Info "Partitioniere Ziel-Disk..."
    $DiskPartOutput = diskpart /s $DiskPartFileName
    $ESPConfigured.Value = $true
    
    if ($DiskPartFileName.Length) { Remove-Item $DiskPartFileName -ErrorAction SilentlyContinue }
}
Catch [Exception] { Cleanup ("Exception in Partition-TargetVHDX") }
}

Function Apply-ImageToTargetVHDX ($ESPDriveLetter, $WindowsDriveLetter) {
try {
    $DismCommand = 'dism /apply-image /imagefile:"' + $WIM + '" /index:1 /applydir:' + $WindowsDriveLetter  + '\'
    Write-Info "Schreibe Daten auf neue Disk. Bitte warten..."
    $DismCaptureOutput = Invoke-Expression $DismCommand
    if (0 -ne $global:lastexitcode) { Cleanup ("Dism Apply fehlgeschlagen.") }
    
    Write-Info "Konfiguriere Boot-Manager (BCDBoot)..."
    $BCDBootCommand = 'bcdboot ' + $WindowsDriveLetter + '\windows /s ' + $ESPDriveLetter + ' /f UEFI'
    $BCDBootOutput = Invoke-Expression $BCDBootCommand
    if (0 -ne $global:lastexitcode) { Cleanup ("BCDBoot fehlgeschlagen.") }
}
Catch [Exception] { Cleanup ("Exception in Apply-ImageToTargetVHDX") }
}

Function Clone-SourceToGeneration2($SourceVM, $SourceBootDiskPath) {
try {
    Write-Info "Konfiguriere neue VM '$NewVMName' basierend auf '$($SourceVM.Name)'..."

    $VMPath = $SourceVM.Path
    if ($Path -ne "") { $VMPath = $Path }

    $NewVM = New-VM -Name $NewVMName -Path $VMPath -MemoryStartupBytes $SourceVM.MemoryStartup -Generation 2 -ErrorAction SilentlyContinue
    if (!$?) { Cleanup ("Fehler beim Erstellen der VM.") }

    Remove-VMNetworkAdapter $NewVM -ErrorAction SilentlyContinue

    # Memory
    try {
        if ($SourceVM.DynamicMemoryEnabled) {
            Set-VM -VM $NewVM -DynamicMemory -MemoryMinimumBytes $SourceVM.MemoryMinimum -MemoryMaximumBytes $SourceVM.MemoryMaximum
        } else {
            set-vm -vm $newvm -StaticMemory
        }
    } catch {}

    # CPU
    try {
        Set-VMProcessor -VM $NewVM -Count (Get-VMProcessor -VM $SourceVM).Count
    } catch {}

    # Disk
    Write-Info " - Füge neue Festplatte hinzu..."
    Add-VMHardDiskDrive $NewVM -Path $VHDX -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -ErrorAction SilentlyContinue
    
    # Network (Simple Copy)
    Write-Info " - Konfiguriere Netzwerk..."
    $SourceNICs = Get-VMNetworkAdapter -VM $SourceVM
    foreach ($nic in $SourceNICs) {
        if ($nic.IsLegacy -eq $False) {
            $newNic = Add-VMNetworkAdapter -VM $NewVM -SwitchName $nic.SwitchName -PassThru
            if ($nic.MacAddressSpoofing) { Set-VMNetworkAdapter -VMNetworkAdapter $newNic -MacAddressSpoofing On }
        } else {
            Write-Warning "Legacy Netzwerkkarte ignoriert (nicht unterstützt in Gen 2)."
        }
    }

    # Boot Order
    $BootDisk = Get-VMHardDiskDrive -VM $NewVM
    Set-VMFirmware -VM $NewVM -FirstBootDevice $BootDisk
}
catch [Exception] { Cleanup ("Exception in Clone-SourceToGeneration2") }
}

# ---------------------------------------------------------------------------------------------------------------------------
# MAIN EXECUTION FLOW
# ---------------------------------------------------------------------------------------------------------------------------

Try {
    if (!$Quiet){
        Write-Host "Hyper-V Gen 1 to Gen 2 Conversion Utility (Modernized)" -fore Yellow
        Write-Host "Based on Microsoft Code by John Howard." -fore Cyan
        Write-Host "changed to newer Server Versions January 2026 by Matthias Körner https://consoro.eu" -fore Cyan
        Write-Host ""
    }

    Validate-Parameters
    PreFlight-Checks

    # Flow
    Locate-SourceBootDisk $script:SourceVMObject ([Ref] $script:SourceBootDiskPath)
    Mount-Disk $script:SourceBootDiskPath ([Ref] $script:SourceBootDiskMounted) 
    Allocate-TwoFreeDriveLetters ([Ref] $script:TargetDriveLetterESP) ([Ref] $script:TargetDriveLetterWindows)
    Validate-SourceWindowsInstallation $script:SourceBootDiskPath ([Ref] $script:SourceBootDiskWindowsPartition) ([Ref] $script:SourceBootDiskWindowsPartitionNum) ([Ref] $script:SourceBootDiskWindowsPartitionUsed)
    Verify-RecoveryEnvironment $script:SourceBootDiskWindowsPartition.DriveLetter
    
    Generate-PathToTargetBootDisk $script:SourceBootDiskPath 
    Create-TargetVHDX $script:SourceBootDiskWindowsPartition.Size 
    Mount-Disk $VHDX ([Ref] $script:TargetBootDiskMounted)
    Partition-TargetVHDX $script:TargetDriveLetterESP $script:TargetDriveLetterWindows ([Ref] $script:TargetDriveESPConfigured)
    
    Capture-ImageOfSourceVHDX $script:SourceBootDiskWindowsPartition.DriveLetter
    Apply-ImageToTargetVHDX $script:TargetDriveLetterESP $script:TargetDriveLetterWindows 
    
    Clone-SourceToGeneration2 $script:SourceVMObject $script:SourceBootDiskPath

    $script:ReachedEndOfProcessing = $True
}
Catch [Exception] {
    Cleanup ("Kritischer Fehler in der Hauptausführung: " + $_.Exception.ToString())
}
Finally {
    Cleanup ""
}
